from datetime import timedelta
from django.utils import timezone
from .models import ConfigurationAPI, ThreatIndicator


def quota_global(request):
    """
    Injecte dans TOUS les templates (via base.html) :
    - le pourcentage de quota API disponible
    - les notifications actives (menaces critiques récentes + quotas bas)
    """
    if not request.user.is_authenticated:
        return {}

    sources_actives = ConfigurationAPI.objects.filter(actif=True)

    pourcentages = []
    sources_quota_bas = []
    for source in sources_actives:
        total_capacite = source.quota_restant + source.quota_consomme
        if total_capacite > 0:
            pct = round((source.quota_restant / total_capacite) * 100)
            pourcentages.append(pct)
            if pct < 20:
                sources_quota_bas.append(source.nom_fournisseur)

    quota_global_pct = round(sum(pourcentages) / len(pourcentages)) if pourcentages else 0

    notifications = []

    # --- Menaces critiques détectées dans les dernières 24h (tous rôles) ---
    depuis_24h = timezone.now() - timedelta(hours=24)
    menaces_recentes = ThreatIndicator.objects.filter(
        updated_at__gte=depuis_24h,
        description__icontains="CRITIQUE"
    ).order_by('-updated_at')

    for menace in menaces_recentes[:5]:
        notifications.append({
            'type': 'menace',
            'texte': f"Menace critique détectée : {menace.indicator_value}",
            'date': menace.updated_at,
        })

    # --- Quotas API bas (admin uniquement) ---
    if request.user.profile.role == 'ADMIN':
        for nom in sources_quota_bas:
            notifications.append({
                'type': 'quota',
                'texte': f"Quota API faible sur {nom}",
                'date': None,
            })

    return {
        'quota_global_pct': quota_global_pct,
        'notifications': notifications,
        'notifications_count': len(notifications),
    }