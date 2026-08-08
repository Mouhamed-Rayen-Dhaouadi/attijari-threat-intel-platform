import requests
from django.utils import timezone
from .models import ConfigurationAPI
from datetime import datetime


class ErreurConnecteur(Exception):
    """Exception levée quand un appel à une source externe échoue proprement."""
    pass


def _get_config_active(nom_fournisseur: str) -> ConfigurationAPI:
    """Récupère une configuration API active, ou lève une erreur claire."""
    try:
        config = ConfigurationAPI.objects.get(nom_fournisseur=nom_fournisseur)
    except ConfigurationAPI.DoesNotExist:
        raise ErreurConnecteur(f"Aucune configuration trouvée pour {nom_fournisseur}.")

    if not config.actif:
        raise ErreurConnecteur(f"La source {nom_fournisseur} est désactivée.")

    if config.quota_restant <= 0:
        raise ErreurConnecteur(f"Quota épuisé pour {nom_fournisseur}.")

    return config


def _enregistrer_usage(config: ConfigurationAPI) -> None:
    """Incrémente le quota consommé et met à jour la date du dernier appel."""
    config.quota_consomme += 1
    config.date_derniere_utilisation = timezone.now()
    config.save()


def interroger_virustotal(valeur: str, type_ioc: str) -> dict:
    """
    Interroge VirusTotal pour une IP, un domaine, une URL ou un hash.
    """
    config = _get_config_active("VT")
    cle = config.get_api_key()
    headers = {"x-apikey": cle}

    endpoints = {
        "IP": f"https://www.virustotal.com/api/v3/ip_addresses/{valeur}",
        "DOMAINE": f"https://www.virustotal.com/api/v3/domains/{valeur}",
        "HASH": f"https://www.virustotal.com/api/v3/files/{valeur}",
        "URL": "https://www.virustotal.com/api/v3/urls",
    }

    if type_ioc not in endpoints:
        raise ErreurConnecteur(f"VirusTotal ne supporte pas le type {type_ioc}.")

    try:
        # MODIFICATION : timeout abaissé de 10 à 3 secondes
        reponse = requests.get(endpoints[type_ioc], headers=headers, timeout=3)
    except requests.exceptions.Timeout:
        raise ErreurConnecteur("VirusTotal : délai d'attente dépassé (timeout).")
    except requests.exceptions.ConnectionError:
        raise ErreurConnecteur("VirusTotal : impossible de joindre le service.")

    _enregistrer_usage(config)

    if reponse.status_code == 401:
        raise ErreurConnecteur("VirusTotal : clé API invalide.")
    if reponse.status_code == 429:
        raise ErreurConnecteur("VirusTotal : quota dépassé côté fournisseur.")
    if reponse.status_code == 404:
        return {"source": "virustotal", "brut": {}, "reputation": "inconnu"}
    if reponse.status_code != 200:
        raise ErreurConnecteur(f"VirusTotal : erreur inattendue ({reponse.status_code}).")

    donnees = reponse.json()
    stats = donnees.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malveillant = stats.get("malicious", 0)

    return {
        "source": "virustotal",
        "brut": donnees,
        "reputation": "malveillant" if malveillant > 0 else "propre",
        "nb_detections": malveillant,
    }


def interroger_abuseipdb(valeur: str, type_ioc: str) -> dict:
    """
    Interroge AbuseIPDB (uniquement pertinent pour les IP).
    """
    if type_ioc != "IP":
        return {"source": "abuseipdb", "brut": {}, "reputation": "non applicable"}

    config = _get_config_active("ABUSEIPDB")
    cle = config.get_api_key()
    headers = {"Key": cle, "Accept": "application/json"}
    params = {"ipAddress": valeur, "maxAgeInDays": 90}

    try:
        # MODIFICATION : timeout abaissé de 10 à 3 secondes
        reponse = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers, params=params, timeout=3,
        )
    except requests.exceptions.Timeout:
        raise ErreurConnecteur("AbuseIPDB : délai d'attente dépassé (timeout).")
    except requests.exceptions.ConnectionError:
        raise ErreurConnecteur("AbuseIPDB : impossible de joindre le service.")

    _enregistrer_usage(config)

    if reponse.status_code == 401:
        raise ErreurConnecteur("AbuseIPDB : clé API invalide.")
    if reponse.status_code == 429:
        raise ErreurConnecteur("AbuseIPDB : quota dépassé côté fournisseur.")
    if reponse.status_code != 200:
        raise ErreurConnecteur(f"AbuseIPDB : erreur inattendue ({reponse.status_code}).")

    donnees = reponse.json()
    score = donnees.get("data", {}).get("abuseConfidenceScore", 0)

    return {
        "source": "abuseipdb",
        "brut": donnees,
        "reputation": "malveillant" if score >= 50 else "propre",
        "score_confiance": score,
    }


def interroger_nvd(cve_id: str) -> dict:
    """
    Interroge la NVD (National Vulnerability Database, NIST) pour une CVE.
    """
    try:
        # MODIFICATION : timeout abaissé de 10 à 3 secondes
        reponse = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": cve_id},
            timeout=3,
        )
    except requests.exceptions.Timeout:
        raise ErreurConnecteur("NVD : délai d'attente dépassé (timeout).")
    except requests.exceptions.ConnectionError:
        raise ErreurConnecteur("NVD : impossible de joindre le service.")

    if reponse.status_code == 403:
        raise ErreurConnecteur("NVD : quota dépassé (essaie à nouveau dans quelques secondes).")
    if reponse.status_code != 200:
        raise ErreurConnecteur(f"NVD : erreur inattendue ({reponse.status_code}).")

    donnees = reponse.json()
    vulnerabilities = donnees.get("vulnerabilities", [])

    if not vulnerabilities:
        return {"source": "nvd", "brut": {}, "reputation": "inconnu"}

    cve_data = vulnerabilities[0].get("cve", {})
    metrics = cve_data.get("metrics", {})

    score_cvss = None
    severite_cvss = None
    for version in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if version in metrics and metrics[version]:
            cvss_data = metrics[version][0]["cvssData"]
            score_cvss = cvss_data.get("baseScore")
            severite_cvss = metrics[version][0].get("baseSeverity", cvss_data.get("baseSeverity"))
            break

    return {
        "source": "nvd",
        "brut": donnees,
        "reputation": "malveillant" if score_cvss and score_cvss >= 7 else "propre",
        "score_cvss": score_cvss,
        "severite_cvss": severite_cvss,
    }
def interroger_threatfox_recentes(jours=1):
    """
    Récupère les IOC récemment ajoutés à ThreatFox (abuse.ch).
    Retourne une liste vide (sans planter) si la source n'est pas
    configurée ou si l'appel échoue — cette fonctionnalité de découverte
    ne doit jamais bloquer toute la page si une seule source a un souci.
    """
    try:
        config = _get_config_active("THREATFOX")
    except ErreurConnecteur:
        return []

    headers = {"Auth-Key": config.get_api_key()}
    payload = {"query": "get_iocs", "days": jours}

    try:
        reponse = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json=payload, headers=headers, timeout=10,
        )
    except requests.exceptions.RequestException:
        return []

    if reponse.status_code != 200:
        return []

    _enregistrer_usage(config)

    donnees = reponse.json()
    resultats = []

    for item in donnees.get("data", []):
        type_brut = item.get("ioc_type", "")
        valeur = item.get("ioc", "")

        if type_brut == "ip:port":
            valeur = valeur.split(":")[0]
            type_final = "IP"
        elif type_brut == "domain":
            type_final = "DOMAINE"
        elif type_brut in ("md5_hash", "sha256_hash"):
            type_final = "HASH"
        elif type_brut == "url":
            type_final = "DOMAINE"
        else:
            continue

        date_decouverte = None
        brut_date = item.get("first_seen")
        if brut_date:
            try:
                date_decouverte = datetime.strptime(
                    brut_date.replace(" UTC", ""), "%Y-%m-%d %H:%M:%S"
                )
            except ValueError:
                pass

        resultats.append({
            "valeur": valeur,
            "type": type_final,
            "date_decouverte": date_decouverte,
            "source_feed": "ThreatFox",
            "malware": item.get("malware_printable") or "Inconnu",
        })

    return resultats


def interroger_feodo_tracker():
    """
    Récupère la liste (recommandée, donc filtrée pour limiter les faux
    positifs) des serveurs de commande-et-contrôle bancaires actifs
    (Dridex, Emotet, TrickBot, QakBot...). Aucune clé API nécessaire.
    """
    try:
        reponse = requests.get(
            "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json",
            timeout=10,
        )
    except requests.exceptions.RequestException:
        return []

    if reponse.status_code != 200:
        return []

    donnees = reponse.json()
    resultats = []

    for item in donnees:
        date_decouverte = None
        brut_date = item.get("first_seen")
        if brut_date:
            try:
                date_decouverte = datetime.strptime(brut_date, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                pass

        resultats.append({
            "valeur": item.get("ip_address"),
            "type": "IP",
            "date_decouverte": date_decouverte,
            "source_feed": "Feodo Tracker",
            "malware": item.get("malware") or "Inconnu",
        })

    return resultats

import ipaddress


def _est_ip_privee(valeur):
    """Détecte les IP privées/réservées, non géolocalisables (RFC 1918, loopback...)."""
    try:
        ip_obj = ipaddress.ip_address(valeur)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
    except ValueError:
        return True  # pas une IP valide du tout


def geolocaliser_ip(valeur):
    """
    Géolocalise une IP via ip-api.com (gratuit, sans clé, 45 req/min).
    Retourne un dict avec pays/ville/latitude/longitude, ou un dict
    marqué "introuvable" si l'IP est privée ou non géolocalisable.
    """
    if _est_ip_privee(valeur):
        return {"introuvable": True}

    try:
        reponse = requests.get(
            f"http://ip-api.com/json/{valeur}",
            params={"fields": "status,country,countryCode,city,lat,lon"},
            timeout=5,
        )
    except requests.exceptions.RequestException:
        return {"introuvable": True}

    if reponse.status_code != 200:
        return {"introuvable": True}

    donnees = reponse.json()
    if donnees.get("status") != "success":
        return {"introuvable": True}

    return {
        "introuvable": False,
        "pays": donnees.get("country", ""),
        "code_pays": donnees.get("countryCode", ""),
        "ville": donnees.get("city", ""),
        "latitude": donnees.get("lat"),
        "longitude": donnees.get("lon"),
    }