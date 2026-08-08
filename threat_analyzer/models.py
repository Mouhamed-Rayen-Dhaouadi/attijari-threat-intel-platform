from django.db import models
from django.contrib.auth.models import User
class ThreatIndicator(models.Model):
    INDICATOR_TYPES = [
        ('IP', 'Adresse IP'),
        ('DOMAINE', 'Nom de Domaine'),
        ('HASH', 'Fichier Hash'),
        ('CVE', 'Vulnérabilité CVE'),
    ]

    SOURCES = [
        ('SCAN_AUTO', 'Scan automatique (API)'),
        ('PARE_FEU', 'Pare-feu'),
        ('SIEM', 'SIEM'),
        ('RENSEIGNEMENT_EXTERNE', 'Renseignement externe'),
        ('INVESTIGATION_MANUELLE', 'Investigation manuelle'),
        ('AUTRE', 'Autre'),
    ]

    indicator_value = models.CharField(max_length=255, unique=True)
    indicator_type = models.CharField(max_length=10, choices=INDICATOR_TYPES)
    description = models.TextField()
    updated_at = models.DateTimeField(auto_now=True)

    source = models.CharField(max_length=30, choices=SOURCES, default='SCAN_AUTO')
    ajoute_par = models.ForeignKey(
        'auth.User', on_delete=models.SET_NULL, null=True, blank=True,
        related_name='iocs_ajoutes',
        help_text="Analyste ayant ajouté manuellement cet IOC (vide si scan automatique)."
    )

    def __str__(self):
        return f"{self.indicator_type} - {self.indicator_value}"


class ScanHistory(models.Model):
    # Clé étrangère : Si l'IoC est supprimé, son historique l'est aussi
    indicator = models.ForeignKey(ThreatIndicator, on_delete=models.CASCADE, related_name='scans')
    # Tracabilité de l'utilisateur (optionnel, mis à Null si recherche anonyme)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    scanned_at = models.DateTimeField(auto_now_add=True)  # Date et heure exacte de la recherche

    def __str__(self):
        return f"Scan de {self.indicator.indicator_value} le {self.scanned_at}"

class ConfigurationAPI(models.Model):
    nom_fournisseur = models.CharField(max_length=50, unique=True, help_text="Ex: VT, ABUSEIPDB")
    cle_api = models.CharField(max_length=255, help_text="La clé secrète fournie par le fournisseur")
    actif = models.BooleanField(default=True)
    quota_restant = models.IntegerField(default=1000)
    quota_consomme = models.IntegerField(default=0)
    date_derniere_utilisation = models.DateTimeField(null=True, blank=True)

    def get_api_key(self) -> str:
        """Retourne la clé API (utilisée par le script de ton collègue)."""
        return self.cle_api

    def __str__(self):
        return f"Configuration {self.nom_fournisseur} ({'Actif' if self.actif else 'Inactif'})"

class Menace(models.Model):
    """
    Confirmation par un analyste qu'un IOC est une vraie menace à
    surveiller/traiter. Distinct de ThreatIndicator, qui contient TOUS
    les IOC analysés (y compris les IOC sains).
    """
    indicator = models.OneToOneField(ThreatIndicator, on_delete=models.CASCADE, related_name='menace')
    confirme_par = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='menaces_confirmees')
    confirme_le = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Menace confirmée : {self.indicator.indicator_value}"


class FileDeploiement(models.Model):
    """
    File d'attente des menaces confirmées à déployer manuellement dans
    les systèmes de protection de la banque (pare-feu, IPS...).
    Retirer une entrée de cette table = "c'est fait, déployé".
    """
    menace = models.OneToOneField(Menace, on_delete=models.CASCADE, related_name='deploiement')
    ajoute_par = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='deploiements_ajoutes')
    ajoute_le = models.DateTimeField(auto_now_add=True)

def __str__(self):
        return f"À déployer : {self.menace.indicator.indicator_value}"
class Investigation(models.Model):
        STATUTS = [
        ('OUVERTE', 'Ouverte'),
        ('FERMEE', 'Fermée'),
     ]
        titre = models.CharField(max_length=255)
        description = models.TextField(blank=True)
        statut = models.CharField(max_length=10, choices=STATUTS, default='OUVERTE')
        indicateurs = models.ManyToManyField(ThreatIndicator, related_name='investigations', blank=True)
        cree_par = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='investigations_creees')
        cree_le = models.DateTimeField(auto_now_add=True)
        maj_le = models.DateTimeField(auto_now=True)
def __str__(self):
        return f"{self.titre} ({self.get_statut_display()})"


class GeolocalisationIP(models.Model):
    """
    Cache des résultats de géolocalisation (ip-api.com), pour éviter de
    ré-interroger l'API à chaque affichage de la carte pour une IP déjà
    connue. Une ligne par IP, jamais dupliquée.
    """
    ip_address = models.CharField(max_length=45, unique=True)
    pays = models.CharField(max_length=100, blank=True)
    code_pays = models.CharField(max_length=2, blank=True)
    ville = models.CharField(max_length=100, blank=True)
    latitude = models.FloatField(null=True, blank=True)
    longitude = models.FloatField(null=True, blank=True)
    introuvable = models.BooleanField(default=False)
    maj_le = models.DateTimeField(auto_now=True)

def __str__(self):
        return f"{self.ip_address} -> {self.pays or 'Inconnu'}"