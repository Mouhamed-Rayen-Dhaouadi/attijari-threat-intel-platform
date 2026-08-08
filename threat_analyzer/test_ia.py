import json
import threading
import requests

# 🔒 Verrou global : Ollama ne traite qu'une requête à la fois.
# Ce verrou empêche les requêtes de s'empiler dans sa queue interne
# sans que Django ne le sache (ce qui provoquait l'effet "boule de neige"
# de timeouts en cascade).
_ollama_lock = threading.Lock()

# ⚠️ Avec le streaming, ce timeout ne s'applique PLUS à la durée totale
# de génération, mais seulement à l'écart maximal toléré entre deux
# paquets de données (deux tokens ou groupes de tokens) reçus d'Ollama.
# Tant qu'Ollama produit du texte régulièrement, la connexion ne
# timeout jamais, même si la génération complète dure 60-90s.
# Une valeur de 20-30s est largement suffisante pour couvrir même un
# "trou" ponctuel (ex : le tout premier token, qui peut être plus long
# à sortir que les suivants).
OLLAMA_STREAM_TIMEOUT = 30.0

# Si le verrou est déjà pris par un autre scan en cours, on attend.
# Peut rester élevé sans risque puisque, avec le streaming, un scan qui
# tourne normalement ne "bloque" plus la file d'attente pendant une
# durée imprévisible : il progresse en continu.
LOCK_WAIT_TIMEOUT = 60.0


def generer_analyse_ia(ioc_value, ioc_type, summary_brut):
    """
    Demande à Llama 3.2 une analyse en streaming via localhost.

    Le streaming (stream: True) est essentiel ici : il évite d'avoir à
    deviner un timeout unique censé couvrir toute la durée de
    génération (souvent longue et variable sur CPU). À la place, on
    accumule les tokens au fur et à mesure, et le timeout HTTP ne
    sanctionne qu'une vraie interruption (silence prolongé), pas une
    génération simplement longue mais régulière.
    """
    url = "http://localhost:11434/api/chat"

    prompt = (
        f"Tu es un analyste SOC expert en Threat Intelligence.\n"
        f"Génère une analyse rapide, concise et professionnelle en français pour cet indicateur de menace :\n\n"
        f"- Valeur de l'IoC : {ioc_value}\n"
        f"- Type d'IoC : {ioc_type}\n"
        f"- Données brutes de détection : {summary_brut}\n\n"
        f"Donne une conclusion claire (Sain ou Menace suspectée) et une recommandation rapide."
    )

    payload = {
        "model": "llama3.2:latest",
        "messages": [{"role": "user", "content": prompt}],
        "stream": True,
        # 🔥 Garde le modèle chargé en mémoire pendant 30 minutes après
        # chaque appel. Évite qu'Ollama décharge le modèle entre deux
        # scans, ce qui provoquerait un rechargement lent (cold-start)
        # à chaque nouvelle requête.
        "keep_alive": "30m",
        "options": {
            # Limite le nombre de tokens générés pour accélérer la
            # réponse sur CPU. Ajustez selon la longueur de rapport
            # souhaitée (environ 300-400 tokens ≈ un paragraphe dense).
            "num_predict": 350,
        },
    }

    # On tente d'acquérir le verrou. Si un autre scan est déjà en train
    # de parler à Ollama, on attend un peu, mais pas indéfiniment.
    acquired = _ollama_lock.acquire(timeout=LOCK_WAIT_TIMEOUT)
    if not acquired:
        return (
            f"Le moteur IA est resté occupé plus de {int(LOCK_WAIT_TIMEOUT)}s par une "
            f"autre analyse. Cela peut indiquer qu'Ollama est anormalement lent ou "
            f"bloqué — vérifiez son état (ex: `ollama ps`, logs du service)."
        )

    try:
        texte_complet = ""

        with requests.post(url, json=payload, stream=True, timeout=OLLAMA_STREAM_TIMEOUT) as reponse:
            if reponse.status_code != 200:
                return f"L'IA n'a pas pu générer l'analyse (Code : {reponse.status_code})."

            # Ollama envoie une ligne JSON par token/groupe de tokens
            # généré. On les concatène jusqu'à recevoir "done": true.
            for ligne in reponse.iter_lines():
                if not ligne:
                    continue
                try:
                    morceau = json.loads(ligne)
                except json.JSONDecodeError:
                    continue

                texte_complet += morceau.get('message', {}).get('content', '')

                if morceau.get('done'):
                    break

        if not texte_complet.strip():
            return "L'IA a renvoyé une réponse vide."

        return texte_complet.strip()

    except requests.exceptions.Timeout:
        return (
            f"Ollama n'a produit aucune donnée pendant plus de "
            f"{int(OLLAMA_STREAM_TIMEOUT)}s (silence anormal, pas juste une génération "
            f"longue). Vérifiez que le service Ollama répond toujours."
        )
    except requests.exceptions.ConnectionError:
        return "Impossible de joindre le serveur Ollama (vérifiez qu'il est démarré)."
    except Exception as e:
        return f"Rapport IA indisponible (Erreur : {str(e)})."
    finally:
        # Toujours relâcher le verrou, même en cas d'exception, pour ne
        # jamais bloquer les scans suivants.
        _ollama_lock.release()