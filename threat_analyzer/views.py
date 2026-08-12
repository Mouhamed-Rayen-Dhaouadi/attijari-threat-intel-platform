from django.shortcuts import render
from .connecteurs import (
    interroger_virustotal, interroger_abuseipdb, interroger_nvd, ErreurConnecteur,
    interroger_threatfox_recentes, interroger_feodo_tracker,
)
import re
from django.utils import timezone
from datetime import timedelta
from .models import ScanHistory, ThreatIndicator
from .forms import AjoutManuelIOCForm, ConfigurationAPIForm
from .models import ConfigurationAPI
from accounts.decorators import role_required
from django.shortcuts import  redirect, get_object_or_404
from django.contrib import messages

# Service Llama 3.2
from .ai_service import generer_analyse_ia
from django.http import HttpResponse
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from accounts.decorators import role_required

# Import pour la gestion stricte du timeout d'Ollama
import concurrent.futures
from .models import Menace, FileDeploiement
from .models import Investigation
from .forms import InvestigationForm
import json
from .models import GeolocalisationIP
from .connecteurs import geolocaliser_ip


# ⏱️ Timeout externe (côté Django) : DOIT être plus grand que le timeout
# HTTP interne défini dans ai_service.py (OLLAMA_HTTP_TIMEOUT = 25s),
# pour laisser le temps à la requête interne de se terminer proprement
# avant que Django n'abandonne. Sinon les deux timeouts se déclenchent
# en même temps de façon imprévisible.
# ⚠️ C'est le SEUL plafond qui limite encore la durée totale de la
# requête Django, même avec le streaming côté ai_service.py (qui lui
# ne timeout plus que sur un silence anormal, pas sur la durée totale).
# Doit être assez large pour laisser sortir l'intégralité des tokens
# générés (num_predict=350) même sur un CPU lent.
TIMEOUT_EXTERNE_IA = 120.0

@role_required('ANALYST', 'ADMIN', 'VIEWER')
def dashboard_view(request):
    maintenant = timezone.now()

    debut_aujourdhui = maintenant.replace(hour=0, minute=0, second=0, microsecond=0)
    debut_mois = maintenant.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    debut_30_jours = maintenant - timedelta(days=29)  # inclut aujourd'hui = 30 jours au total

    # --- KPI cards ---
    total_scans_historique = ScanHistory.objects.count()
    scans_aujourdhui = ScanHistory.objects.filter(scanned_at__gte=debut_aujourdhui).count()
    scans_ce_mois = ScanHistory.objects.filter(scanned_at__gte=debut_mois).count()

    tous_les_iocs = ThreatIndicator.objects.all()
    total_unique_ioc = tous_les_iocs.count()

    malicious_count = tous_les_iocs.filter(
        description__icontains="CRITIQUE"
    ).count() + tous_les_iocs.filter(
        description__icontains="ELEVE"
    ).exclude(description__icontains="CRITIQUE").count()

    # --- Quota API : moyenne des sources actives ---
    sources_actives = ConfigurationAPI.objects.filter(actif=True)
    if sources_actives.exists():
        pourcentages = []
        for source in sources_actives:
            total_capacite = source.quota_restant + source.quota_consomme
            if total_capacite > 0:
                pourcentage = round((source.quota_restant / total_capacite) * 100)
                pourcentages.append(pourcentage)
        quota_restant_pct = round(sum(pourcentages) / len(pourcentages)) if pourcentages else 0
    else:
        quota_restant_pct = 0

    # --- Graphique : scans par jour (30 derniers jours) ---
    scan_days = []
    scan_counts = []
    for i in range(29, -1, -1):
        jour = (maintenant - timedelta(days=i)).date()
        debut_jour = timezone.make_aware(timezone.datetime.combine(jour, timezone.datetime.min.time()))
        fin_jour = debut_jour + timedelta(days=1)
        count = ScanHistory.objects.filter(scanned_at__gte=debut_jour, scanned_at__lt=fin_jour).count()
        scan_days.append(jour.strftime("%d/%m"))
        scan_counts.append(count)

    # --- Répartition par type d'IOC (tout l'historique) ---
    types_labels = ['IP', 'DOMAINE', 'HASH', 'CVE']
    ioc_type_counts_raw = {t: tous_les_iocs.filter(indicator_type=t).count() for t in types_labels}
    ioc_type_labels = [t for t in types_labels if ioc_type_counts_raw[t] > 0]
    ioc_type_counts = [ioc_type_counts_raw[t] for t in ioc_type_labels]

    # --- Répartition par sévérité (tout l'historique) ---
    severity_counts = {
        'critique': tous_les_iocs.filter(description__icontains="CRITIQUE").count(),
        'eleve': tous_les_iocs.filter(description__icontains="ELEVE").exclude(description__icontains="CRITIQUE").count(),
        'moyen': tous_les_iocs.filter(description__icontains="MOYEN").exclude(description__icontains="CRITIQUE").exclude(description__icontains="ELEVE").count(),
    }
    severity_counts['faible'] = total_unique_ioc - sum(severity_counts.values())

    context = {
        'total_scans': total_scans_historique,
        'scans_today': scans_aujourdhui,
        'scans_month': scans_ce_mois,
        'total_unique_ioc': total_unique_ioc,
        'unique_iocs': total_unique_ioc,
        'malicious_count': malicious_count,
        'quota_restant': quota_restant_pct,
        'scan_days': scan_days,
        'scan_counts': scan_counts,
        'ioc_type_labels': ioc_type_labels,
        'ioc_type_counts': ioc_type_counts,
        'severity_counts': severity_counts,
    }
    return render(request, 'threat_analyzer/dashboard.html', context)


def _executer_pipeline_analyse(user_input, ioc_type):
    """
    Fonction helper interne pour centraliser l'interrogation des API externes
    et la génération du rapport rédigé par Llama 3.2.

    NOTE IMPORTANTE : même si `future.result(timeout=...)` expire côté Django,
    le thread lancé par ThreadPoolExecutor n'est PAS annulé automatiquement -
    il continue de tourner en arrière-plan jusqu'à ce que la requête HTTP vers
    Ollama se termine (succès, erreur, ou son propre timeout interne).
    C'est pour cette raison que ai_service.py utilise désormais un verrou
    global (_ollama_lock) : cela empêche plusieurs de ces threads "fantômes"
    de s'empiler dans la queue d'Ollama et de dégrader les temps de réponse
    au fil des scans successifs.
    """
    severity = "faible"
    summary = ""

    try:
        if ioc_type == "CVE":
            nvd_res = interroger_nvd(user_input)
            if nvd_res['reputation'] == "malveillant":
                severity = "critique" if nvd_res['score_cvss'] and nvd_res['score_cvss'] >= 9.0 else "eleve"
                summary = f"NVD : Score CVSS: {nvd_res['score_cvss']} ({nvd_res['severite_cvss']})."
            else:
                summary = f"NVD : Faille modérée (Score CVSS: {nvd_res.get('score_cvss', 'Inconnu')})."
        else:
            vt_res = interroger_virustotal(user_input, ioc_type)
            nb_detections = vt_res.get('nb_detections', 0)
            if vt_res['reputation'] == "malveillant":
                severity = "critique" if nb_detections > 10 else "eleve"
                summary = f"VirusTotal : Signalé par {nb_detections} moteurs."
            else:
                summary = "VirusTotal : Sain."

            if ioc_type == "IP":
                abuse_res = interroger_abuseipdb(user_input, ioc_type)
                if abuse_res['reputation'] == "malveillant":
                    severity = "critique"
                    summary += f" | AbuseIPDB : Suspicion ({abuse_res['score_confiance']}%)."

    except ErreurConnecteur as e:
        severity = "moyen"
        summary = f"Erreur technique : {str(e)}"

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(generer_analyse_ia, user_input, ioc_type, summary)
            analyse_redigee = future.result(timeout=TIMEOUT_EXTERNE_IA)

    except concurrent.futures.TimeoutError:
        # Message de secours uniquement si Ollama dépasse le délai limite.
        analyse_redigee = (
            f"⚠️ [MOTEUR IA INDISPONIBLE]\n"
            f"Le serveur Ollama a dépassé le temps limite de réponse SecOps "
            f"({int(TIMEOUT_EXTERNE_IA)}s).\n\n"
            f"SYNTHÈSE TECHNIQUE DIRECTE DES CONNECTEURS :\n"
            f"• Contexte de l'indicateur : Analyse immédiate effectuée pour le type [{ioc_type}].\n"
            f"• Évaluation des plateformes : {summary}"
        )
    except Exception as ai_error:
        # Filet de sécurité pour toute autre erreur imprévue côté thread.
        analyse_redigee = (
            f"⚠️ [MOTEUR IA INDISPONIBLE]\n"
            f"Erreur inattendue lors de la génération du rapport IA : {str(ai_error)}\n\n"
            f"SYNTHÈSE TECHNIQUE DIRECTE DES CONNECTEURS :\n"
            f"• Contexte de l'indicateur : Analyse immédiate effectuée pour le type [{ioc_type}].\n"
            f"• Évaluation des plateformes : {summary}"
        )

    return severity, analyse_redigee
@role_required('ANALYST', 'ADMIN')
def ioc_scanner_view(request):
    context = {}
    is_cached_result = False

    if request.method == "POST":
        user_input = request.POST.get('ioc_input', '').strip()
        force_update = "action_force_update" in request.POST  # Détection du bouton de rafraîchissement

        if user_input:
            # Identification du type (Regex)
            if re.match(r'^CVE-\d{4}-\d{4,7}$', user_input, re.IGNORECASE):
                ioc_type = "CVE"
            elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', user_input):
                ioc_type = "IP"
            elif re.match(r'^[a-fA-F0-9]{64}$', user_input):
                ioc_type = "HASH"
            else:
                ioc_type = "DOMAINE"

            if force_update:
                # 🔄 CAS A : L'analyste force la mise à jour
                indicator, _ = ThreatIndicator.objects.get_or_create(
                    indicator_value=user_input,
                    defaults={'indicator_type': ioc_type}
                )
                severity, analyse_redigee = _executer_pipeline_analyse(user_input, ioc_type)

                indicator.description = f"Gravité: {severity.upper()} | {analyse_redigee}"
                indicator.updated_at = timezone.now()
                indicator.save()
                is_cached_result = False
            else:
                # 🔍 CAS B : Recherche standard
                try:
                    indicator = ThreatIndicator.objects.get(indicator_value=user_input)
                    is_cached_result = True  # On lève le flag pour afficher le bouton "Mettre à jour"
                except ThreatIndicator.DoesNotExist:
                    indicator = ThreatIndicator.objects.create(
                        indicator_value=user_input,
                        indicator_type=ioc_type,
                        description='Analyse en cours...'
                    )
                    severity, analyse_redigee = _executer_pipeline_analyse(user_input, ioc_type)
                    indicator.description = f"Gravité: {severity.upper()} | {analyse_redigee}"
                    indicator.save()
                    is_cached_result = False

            # ÉTAPE HISTORIQUE
            ScanHistory.objects.create(
                indicator=indicator,
                user=request.user if request.user.is_authenticated else None
            )

            # Extraction de la sévérité pour la charte graphique
            current_severity = "faible"
            if "CRITIQUE" in indicator.description: current_severity = "critique"
            elif "ELEVE" in indicator.description: current_severity = "eleve"
            elif "MOYEN" in indicator.description: current_severity = "moyen"

            # Extraction de la synthèse rédigée
            affichage_description = indicator.description.split(" | ", 1)[-1]

            context['result'] = {
                'ioc_value': indicator.indicator_value,
                'ioc_type': indicator.indicator_type,
                'severity': current_severity,
                'context_summary': affichage_description,
                'updated_at': indicator.updated_at
            }
            context['is_cached_result'] = is_cached_result
            context['deja_menace'] = hasattr(indicator, 'menace')

    context['points_json'] = json.dumps(_construire_points_carte())

    return render(request, 'threat_analyzer/scanner.html', context)


@role_required('ANALYST', 'ADMIN')
def database_view(request):
    indicators = ThreatIndicator.objects.all().order_by('-updated_at')
    if request.user.profile.role == 'ADMIN':
        for ioc in indicators:
            derniers_scans = ioc.scans.select_related('user').order_by('-scanned_at')[:5]
            noms_uniques = []
            for s in derniers_scans:
                nom = s.user.username if s.user else "Anonyme"
                if nom not in noms_uniques:
                    noms_uniques.append(nom)
            ioc.scanned_by_list = noms_uniques

    return render(request, 'threat_analyzer/database.html', {'indicators': indicators})

@role_required('ANALYST', 'ADMIN')
def exporter_pdf_view(request, ioc_value):
    """
    Génère un rapport PDF officiel pour un IoC donné.
    """
    try:
        indicator = ThreatIndicator.objects.get(indicator_value=ioc_value)
    except ThreatIndicator.DoesNotExist:
        return HttpResponse("Indicateur introuvable.", status=404)

    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="Rapport_SOC_{ioc_value}.pdf"'

    doc = SimpleDocTemplate(response, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    story = []
    styles = getSampleStyleSheet()

    style_titre = ParagraphStyle(
        'TitreStyle',
        parent=styles['Heading1'],
        fontSize=20,
        textColor=colors.HexColor('#9a1c1f'),
        spaceAfter=15
    )

    style_texte = ParagraphStyle(
        'TexteStyle',
        parent=styles['Normal'],
        fontSize=11,
        textColor=colors.HexColor('#1e293b'),
        leading=16,
        spaceAfter=10
    )

    story.append(Paragraph(f"ATTIJARI BANK - RAPPORT D'INVESTIGATION SOC", style_titre))
    story.append(Paragraph(f"<b>Indicateur :</b> {indicator.indicator_value}", style_texte))
    story.append(Paragraph(f"<b>Type d'IoC :</b> {indicator.indicator_type}", style_texte))
    story.append(Paragraph(f"<b>Date de l'analyse :</b> {indicator.updated_at.strftime('%d/%m/%Y %H:%M')}", style_texte))
    story.append(Spacer(1, 15))

    story.append(Paragraph("<b>CONTENU DE L'ANALYSE IA :</b>", style_texte))
    story.append(Spacer(1, 5))

    texte_ia = indicator.description.split(" | ", 1)[-1]
    for paragraphe in texte_ia.split('\n'):
        if paragraphe.strip():
            story.append(Paragraph(paragraphe, style_texte))

    doc.build(story)
    return response

def _masquer_cle(cle):
    """Ex: 'sk-abc123xyz789' -> 'sk***********789'"""
    if len(cle) <= 8:
        return "*" * len(cle)
    return cle[:2] + "*" * (len(cle) - 6) + cle[-4:]


@role_required('ADMIN')
def liste_api_view(request):
    configurations = ConfigurationAPI.objects.all().order_by('nom_fournisseur')
    for config in configurations:
        config.cle_masquee = _masquer_cle(config.cle_api)
    return render(request, 'threat_analyzer/liste_api.html', {'configurations': configurations})

@role_required('ADMIN')
def creer_api_view(request):
    if request.method == "POST":
        form = ConfigurationAPIForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Source API ajoutée avec succès.")
            return redirect('liste_api')
    else:
        form = ConfigurationAPIForm()

    return render(request, 'threat_analyzer/form_api.html', {'form': form, 'mode': 'creation'})


@role_required('ADMIN')
def modifier_api_view(request, config_id):
    configuration = get_object_or_404(ConfigurationAPI, id=config_id)

    if request.method == "POST":
        form = ConfigurationAPIForm(request.POST, instance=configuration)
        if form.is_valid():
            form.save()
            messages.success(request, "Source API modifiée avec succès.")
            return redirect('liste_api')
    else:
        form = ConfigurationAPIForm(instance=configuration)

    return render(request, 'threat_analyzer/form_api.html', {'form': form, 'mode': 'edition', 'configuration': configuration})


@role_required('ADMIN')
def supprimer_api_view(request, config_id):
    configuration = get_object_or_404(ConfigurationAPI, id=config_id)

    if request.method == "POST":
        configuration.delete()
        messages.success(request, "Source API supprimée.")
        return redirect('liste_api')

    return render(request, 'threat_analyzer/confirmer_suppression_api.html', {'configuration': configuration})

@role_required('ANALYST', 'ADMIN')
def ajouter_ioc_manuel_view(request):
    if request.method == "POST":
        form = AjoutManuelIOCForm(request.POST)
        if form.is_valid():
            valeur = form.cleaned_data['indicator_value'].strip()

            if ThreatIndicator.objects.filter(indicator_value=valeur).exists():
                messages.error(
                    request,
                    f"L'indicateur '{valeur}' existe déjà en base. Utilisez la mise à jour depuis la Threat Database."
                )
                return render(request, 'threat_analyzer/form_ajout_manuel.html', {'form': form})

            description_finale = (
                f"Gravité: {form.cleaned_data['severity']} | "
                f"[AJOUT MANUEL] {form.cleaned_data['description']}"
            )

            ThreatIndicator.objects.create(
                indicator_value=valeur,
                indicator_type=form.cleaned_data['indicator_type'],
                description=description_finale,
                source=form.cleaned_data['source'],
                ajoute_par=request.user,
            )
            messages.success(request, f"Indicateur '{valeur}' ajouté avec succès.")
            return redirect('database')
    else:
        form = AjoutManuelIOCForm()

    return render(request, 'threat_analyzer/form_ajout_manuel.html', {'form': form})
@role_required('ANALYST', 'ADMIN')
def confirmer_menace_view(request, ioc_value):
    indicator = get_object_or_404(ThreatIndicator, indicator_value=ioc_value)

    if hasattr(indicator, 'menace'):
        messages.error(request, "Cet IOC est déjà confirmé comme menace.")
    else:
        Menace.objects.create(indicator=indicator, confirme_par=request.user)
        messages.success(request, f"'{ioc_value}' marqué comme menace confirmée.")

    return redirect('database')


@role_required('ANALYST', 'ADMIN')
def liste_menaces_view(request):
    menaces = Menace.objects.select_related('indicator', 'confirme_par').order_by('-confirme_le')
    return render(request, 'threat_analyzer/liste_menaces.html', {'menaces': menaces})


@role_required('ANALYST', 'ADMIN')
def ajouter_file_deploiement_view(request, menace_id):
    menace = get_object_or_404(Menace, id=menace_id)

    if hasattr(menace, 'deploiement'):
        messages.error(request, "Cette menace est déjà dans la file de déploiement.")
    else:
        FileDeploiement.objects.create(menace=menace, ajoute_par=request.user)
        messages.success(request, f"'{menace.indicator.indicator_value}' ajouté à la file de déploiement.")

    return redirect('liste_menaces')


@role_required('ANALYST', 'ADMIN')
def liste_deploiement_view(request):
    file_attente = FileDeploiement.objects.select_related(
        'menace__indicator', 'ajoute_par'
    ).order_by('-ajoute_le')
    return render(request, 'threat_analyzer/liste_deploiement.html', {'file_attente': file_attente})


@role_required('ADMIN')
def retirer_file_deploiement_view(request, deploiement_id):
    deploiement = get_object_or_404(FileDeploiement, id=deploiement_id)

    if request.method == "POST":
        valeur = deploiement.menace.indicator.indicator_value
        deploiement.delete()
        messages.success(request, f"'{valeur}' retiré de la file — considéré comme déployé.")
        return redirect('liste_deploiement')

    return render(request, 'threat_analyzer/confirmer_retrait_deploiement.html', {'deploiement': deploiement})


@role_required('ANALYST', 'ADMIN')
def decouverte_ioc_view(request):
    resultats_threatfox = interroger_threatfox_recentes(jours=1)
    resultats_feodo = interroger_feodo_tracker()

    tous_resultats = resultats_threatfox + resultats_feodo

    # Tri par date de découverte, le plus récent en premier.
    # Les entrées sans date connue (parsing échoué) sont reléguées à la fin.
    tous_resultats.sort(
        key=lambda r: r['date_decouverte'] or timezone.datetime.min,
        reverse=True
    )

    # On marque les IOC déjà présents en base, pour ne pas proposer de
    # les ajouter une deuxième fois.
    valeurs_existantes = set(ThreatIndicator.objects.values_list('indicator_value', flat=True))
    for r in tous_resultats:
        r['deja_ajoute'] = r['valeur'] in valeurs_existantes

    return render(request, 'threat_analyzer/decouverte_ioc.html', {'resultats': tous_resultats})


@role_required('ANALYST', 'ADMIN')
def ajouter_ioc_decouvert_view(request):
    if request.method == "POST":
        valeur = request.POST.get('valeur', '').strip()
        type_ioc = request.POST.get('type', '')
        malware = request.POST.get('malware', '')
        source_feed = request.POST.get('source_feed', '')

        if ThreatIndicator.objects.filter(indicator_value=valeur).exists():
            messages.error(request, f"'{valeur}' existe déjà en base.")
        else:
            description = (
                f"Gravité: ELEVE | [DÉCOUVERTE {source_feed.upper()}] "
                f"Malware associé : {malware}."
            )
            indicator = ThreatIndicator.objects.create(
                indicator_value=valeur,
                indicator_type=type_ioc,
                description=description,
                source='RENSEIGNEMENT_EXTERNE',
                ajoute_par=request.user,
            )
            Menace.objects.create(indicator=indicator, confirme_par=request.user)
            messages.success(request, f"'{valeur}' ajouté et confirmé comme menace.")

    return redirect('decouverte_ioc')

@role_required('ANALYST', 'ADMIN')
def liste_investigations_view(request):
    investigations = Investigation.objects.all().order_by('-maj_le')
    return render(request, 'threat_analyzer/liste_investigations.html', {'investigations': investigations})


@role_required('ANALYST', 'ADMIN')
def creer_investigation_view(request):
    if request.method == "POST":
        form = InvestigationForm(request.POST)
        if form.is_valid():
            investigation = form.save(commit=False)
            investigation.cree_par = request.user
            investigation.save()
            messages.success(request, "Enquête créée avec succès.")
            return redirect('detail_investigation', investigation_id=investigation.id)
    else:
        form = InvestigationForm()

    return render(request, 'threat_analyzer/form_investigation.html', {'form': form, 'mode': 'creation'})


@role_required('ANALYST', 'ADMIN')
def detail_investigation_view(request, investigation_id):
    investigation = get_object_or_404(Investigation, id=investigation_id)

    if request.method == "POST":
        # Rattachement d'un IOC existant, sélectionné via son ID.
        ioc_id = request.POST.get('ioc_id')
        if ioc_id:
            ioc = get_object_or_404(ThreatIndicator, id=ioc_id)
            investigation.indicateurs.add(ioc)
            messages.success(request, f"'{ioc.indicator_value}' rattaché à l'enquête.")
        return redirect('detail_investigation', investigation_id=investigation.id)

    iocs_rattaches = investigation.indicateurs.all()
    iocs_disponibles = ThreatIndicator.objects.exclude(id__in=iocs_rattaches.values_list('id', flat=True))

    return render(request, 'threat_analyzer/detail_investigation.html', {
        'investigation': investigation,
        'iocs_rattaches': iocs_rattaches,
        'iocs_disponibles': iocs_disponibles,
    })


@role_required('ANALYST', 'ADMIN')
def retirer_ioc_investigation_view(request, investigation_id, ioc_id):
    investigation = get_object_or_404(Investigation, id=investigation_id)
    ioc = get_object_or_404(ThreatIndicator, id=ioc_id)
    investigation.indicateurs.remove(ioc)
    messages.success(request, f"'{ioc.indicator_value}' retiré de l'enquête.")
    return redirect('detail_investigation', investigation_id=investigation.id)



def _code_pays_vers_drapeau(code):
    """Convertit un code pays ISO (ex: 'FR') en emoji drapeau (ex: 🇫🇷)."""
    if not code or len(code) != 2:
        return ""
    return "".join(chr(127397 + ord(c)) for c in code.upper())



def _construire_points_carte():
    """
    Calcule (avec cache via GeolocalisationIP) les points à afficher sur
    la carte, pour toutes les IP déjà scannées. Réutilisé par la page
    Scanner, qui affiche cette carte en permanence.
    """
    ips_scannees = ThreatIndicator.objects.filter(indicator_type='IP')
    points = []

    for ioc in ips_scannees:
        geo, cree = GeolocalisationIP.objects.get_or_create(ip_address=ioc.indicator_value)

        if geo.latitude is None and not geo.introuvable:
            resultat = geolocaliser_ip(ioc.indicator_value)
            geo.introuvable = resultat.get('introuvable', True)
            if not geo.introuvable:
                geo.pays = resultat['pays']
                geo.code_pays = resultat['code_pays']
                geo.ville = resultat['ville']
                geo.latitude = resultat['latitude']
                geo.longitude = resultat['longitude']
            geo.save()

        if not geo.introuvable and geo.latitude is not None:
            description_maj = ioc.description.upper()
            if 'CRITIQUE' in description_maj:
                severite = 'critique'
            elif 'ELEVE' in description_maj:
                severite = 'eleve'
            elif 'MOYEN' in description_maj:
                severite = 'moyen'
            else:
                severite = 'faible'

            points.append({
                'valeur': ioc.indicator_value,
                'pays': geo.pays,
                'drapeau': _code_pays_vers_drapeau(geo.code_pays),
                'ville': geo.ville,
                'latitude': geo.latitude,
                'longitude': geo.longitude,
                'severite': severite,
            })

    return points