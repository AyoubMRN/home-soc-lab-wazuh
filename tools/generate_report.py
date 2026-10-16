"""Generate a local HTML report for recorded PowerShell and correlation tests.

No network calls, AI, incident verdicts or Wazuh engine replay.
"""
import argparse
import base64
from datetime import datetime, timezone
from html import escape
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET
if __package__:
    from .validate_evidence import correlation, load, task, ssh
else:
    from validate_evidence import correlation, load, task, ssh


CORRELATION_CASES = (
    ("Trois commandes rapprochées", "correlation-whoami-three.alerts.jsonl", {"100103": 3}, False, False),
    ("Quatre commandes rapprochées", "correlation-whoami-four.alerts.jsonl", {"100103": 3, "100110": 1}, False, False),
    ("Quatre commandes espacées", "correlation-whoami-spaced.alerts.jsonl", {"100103": 4}, True, False),
    ("Quatre commandes différentes rapprochées", "correlation-mixed-four.alerts.jsonl", {"100100": 1, "100102": 1, "100103": 1, "100110": 1}, False, True),
)


def text(value):
    return escape(str(value), quote=True)


def read_alert(path):
    lines = [line for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    if len(lines) != 1:
        raise ValueError(f"{path.name}: expected exactly one alert")
    row = json.loads(lines[0])
    for keys in (("timestamp",), ("agent", "id"), ("agent", "name"), ("rule", "id"),
                 ("rule", "level"), ("rule", "description"),
                 ("data", "win", "eventdata", "commandLine")):
        value = row
        for key in keys:
            if not isinstance(value, dict) or key not in value:
                raise ValueError(f"{path.name}: missing {'.'.join(keys)}")
            value = value[key]
    datetime.fromisoformat(row["timestamp"])
    return row


def decoded_script(command):
    match = re.search(r"(?i)(?:^|\s)-EncodedCommand\s+([A-Za-z0-9+/=]+)", command)
    if not match:
        return None
    return base64.b64decode(match.group(1), validate=True).decode("utf-16-le")


def read_correlations(folder):
    cases = []
    for label, filename, counts, spaced, mixed in CORRELATION_CASES:
        correlation(folder, filename, None, counts, spaced=spaced, mixed=mixed)
        cases.append((label, filename, load(folder / filename)))
    return cases


def render_correlations(cases):
    if not cases:
        return ""
    summary, details = [], []
    for label, filename, original_rows in cases:
        rows = sorted(original_rows, key=lambda row: datetime.fromisoformat(row["timestamp"]))
        hits = [r for r in rows if r["rule"]["id"] == "100110"]
        outcome = f"{len(hits)} alerte 100110 observée" if hits else "Aucune 100110 dans l’export sélectionné"
        summary.append(f"<tr><td>{text(label)}</td><td>{len(rows)}</td><td>{text(outcome)}</td></tr>")
        timeline = []
        first = datetime.fromisoformat(rows[0]["timestamp"])
        for row in rows:
            moment = datetime.fromisoformat(row["timestamp"])
            win = row["data"]["win"]
            image = win["eventdata"]["image"].replace("\\", "/").split("/")[-1]
            utc = moment.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC"
            timeline.append(f'<tr><td>{text(utc)}</td><td>+{(moment-first).total_seconds():.3f} s</td><td>{text(image)}</td><td>{text(win["system"]["eventRecordID"])}</td><td>{text(row["rule"]["id"])}</td></tr>')
        agent = rows[0]["agent"]
        details.append(f'''<section><h2>{text(label)}</h2><p>{text(agent['name'])} · agent {text(agent['id'])} — {text(outcome)}.</p>
<div class="table-wrap"><table><thead><tr><th>Heure d’alerte UTC</th><th>Écart au début</th><th>Programme</th><th>Événement Windows</th><th>Règle</th></tr></thead><tbody>{''.join(timeline)}</tbody></table></div>
<p>Source : <code>{text(filename)}</code>. Lignes affichées par heure d’alerte ; le fichier original reste inchangé. Les écarts mesurent les horaires d’alertes, pas l’horloge interne du moteur de corrélation.</p></section>''')
    return '''<section><h2>Corrélation des activités de découverte</h2>
<p>Quatre essais conservés sur Windows-Endpoint. Les résultats ci-dessous sont lus dans les exports historiques ; aucune nouvelle exécution n’est effectuée.</p>
<p class="notice"><strong>Seuil empirique : frequency=7, fenêtre de 60 secondes.</strong> Ce réglage a donné un déclenchement au quatrième événement dans les essais rapprochés. Il compense un comportement de comptage observé dont la cause reste ouverte. La règle compte les événements : elle ne garantit pas des commandes différentes et une activité d’administration légitime peut déclencher la même alerte.</p>
<div class="table-wrap"><table><thead><tr><th>Essai</th><th>Événements conservés</th><th>Résultat observé</th></tr></thead><tbody>''' + ''.join(summary) + '''</tbody></table></div>
<p>Les exports sont sélectionnés par heure et par règle. Une absence de 100110 dans un export ne prouve ni une collecte exhaustive, ni une absence générale d’activité.</p></section>''' + ''.join(details)


def read_task(folder):
    task(folder)
    return load(folder / "scheduled-task-created.alerts.jsonl")[0]


def render_task(row):
    if row is None:
        return ""
    win, rule, agent = row["data"]["win"], row["rule"], row["agent"]
    utc = datetime.fromisoformat(row["timestamp"]).astimezone(timezone.utc).isoformat()
    event_utc = win["system"]["systemTime"]
    mitre = ", ".join(rule.get("mitre", {}).get("id", [])) or "Non renseigné"
    return f'''<section><h2>Création d’une tâche planifiée</h2>
<p>La création de la tâche de laboratoire a produit une alerte native Wazuh. Les identifiants de l’événement, le nom de tâche et l’ordinateur ont été comparés au XML Windows conservé avant la génération du rapport.</p>
<dl><dt>Machine</dt><dd>{text(agent['name'])} · agent {text(agent['id'])}</dd>
<dt>Tâche</dt><dd>{text(win['eventdata']['taskName'])}</dd>
<dt>Compte déclaré dans l’événement</dt><dd>{text(win['eventdata'].get('userContext', 'Non renseigné'))}</dd>
<dt>Journal Windows</dt><dd>{text(win['system']['channel'])}</dd>
<dt>Événement / numéro d’enregistrement</dt><dd>{text(win['system']['eventID'])} / {text(win['system']['eventRecordID'])}</dd>
<dt>Heure de l’événement Windows (UTC)</dt><dd>{text(event_utc)}</dd>
<dt>Heure de l’alerte Wazuh (UTC)</dt><dd>{text(utc)}</dd>
<dt>Règle native</dt><dd>{text(rule['id'])} · niveau {text(rule['level'])}</dd>
<dt>Description originale</dt><dd>{text(rule['description'])}</dd>
<dt>MITRE ATT&amp;CK</dt><dd>{text(mitre)}</dd>
<dt>Identifiant de l’alerte</dt><dd>{text(row.get('id', 'Non renseigné'))}</dd></dl>
<h3>Ce que les fichiers permettent d’établir</h3>
<div class="table-wrap"><table><thead><tr><th>Point examiné</th><th>Conclusion</th></tr></thead><tbody>
<tr><td>Création de la tâche</td><td>Confirmée par l’événement Windows 106 et l’alerte native 67014.</td></tr>
<tr><td>Détection de l’exécution dans Wazuh</td><td>Non démontrée. L’alerte de création ne prouve pas l’exécution de l’action.</td></tr>
<tr><td>Résultat local d’exécution et nettoyage</td><td>Vérifiés manuellement pendant le laboratoire ; leurs captures restent des preuves séparées et ne sont pas contrôlées par ce rapport.</td></tr>
</tbody></table></div>
<p class="notice"><strong>Simulation inoffensive.</strong> La tâche a été créée sans déclencheur automatique pour un lancement manuel. Son association à T1053.005 ne suffit pas à conclure à une persistance malveillante.</p>
<h3>Vérifications proposées</h3><ul><li>Vérifier l’auteur, l’action, les déclencheurs et les droits de la tâche.</li><li>Rechercher les événements de lancement et le processus enfant pour établir l’exécution.</li><li>Comparer avec les opérations d’administration attendues.</li></ul>
<p>Sources : <code>scheduled-task-created.alerts.jsonl</code> et <code>scheduled-task-created.event106.xml</code>. L’alerte ne contient pas de full_log. Le XML est une copie de contenu transmise par le presse-papiers et la conversation ; son identité binaire avec le fichier original n’a pas été vérifiée. Il n’est pas directement validé pour un rejeu Wazuh.</p></section>'''


def render_ssh(rows):
    if not rows:
        return ""
    timeline = []
    first = datetime.fromisoformat(rows[0]["timestamp"])
    for row in rows:
        moment = datetime.fromisoformat(row["timestamp"])
        utc = moment.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC"
        timeline.append(f'<tr><td>{text(utc)}</td><td>+{(moment-first).total_seconds():.3f} s</td><td>{text(row["data"]["srcport"])}</td><td>{text(row["rule"]["id"])}</td><td>{text(row["rule"]["level"])}</td></tr>')
    final = rows[-1]
    return f'''<section><h2>SSH : échecs répétés sur Ubuntu</h2>
<p class="notice"><strong>Simulation contrôlée :</strong> huit tentatives avec un mot de passe volontairement incorrect, depuis le PC du laboratoire vers le compte existant vboxuser. La description native parle de brute force ; ce test autorisé n’est pas un incident confirmé.</p>
<dl><dt>Machine surveillée</dt><dd>{text(final['agent']['name'])} · agent {text(final['agent']['id'])} · {text(final['agent'].get('ip', 'Non renseignée'))}</dd>
<dt>Adresse source / compte ciblé</dt><dd>{text(final['data']['srcip'])} / {text(final['data']['dstuser'])}</dd>
<dt>Résultat observé</dt><dd>Sept alertes individuelles 5760 (niveau 5), puis une corrélation native 5763 (niveau 10).</dd>
<dt>Description native</dt><dd>{text(final['rule']['description'])}</dd>
<dt>Seuil de l’alerte</dt><dd>{text(final['rule']['frequency'])} événements. Fenêtre de 120 secondes et ignore de 60 secondes relevés manuellement dans la règle installée ; son fichier XML reste à exporter.</dd>
<dt>MITRE ATT&amp;CK</dt><dd>{text(', '.join(final['rule'].get('mitre', {}).get('id', [])))}</dd></dl>
<div class="table-wrap"><table><thead><tr><th>Heure d’alerte UTC</th><th>Écart au début</th><th>Port source</th><th>Règle</th><th>Niveau</th></tr></thead><tbody>{''.join(timeline)}</tbody></table></div>
<h3>Événement source déclencheur</h3><pre>{text(final['full_log'])}</pre>
<p>Le validateur compare les sept lignes de previous_output aux sept échecs précédents de cet export, contrôle les sources distinctes et leur intervalle inférieur à 120 secondes. Ce contrôle relit les preuves historiques ; il ne rejoue pas le moteur Wazuh.</p>
<h3>Vérifications proposées</h3><ul><li>Confirmer le compte ciblé, la provenance et le contexte des tentatives.</li><li>Chercher une éventuelle connexion réussie après les échecs.</li><li>Vérifier les autres comptes ou machines concernés avant de décider d’une réponse.</li></ul>
<p>Source : <code>ssh-eight-failures.alerts.jsonl</code>. Les horaires du journal source Ubuntu et ceux des alertes sont différents ; les écarts du tableau concernent uniquement les alertes. Aucun temps de détection fiable n’est déduit. Les essais avec une autre adresse source et hors fenêtre ne sont pas démontrés par ce fichier. L’échec isolé a été vérifié séparément dans le tableau de bord, sans export intégré ici.</p></section>'''


def render(rows, correlations=None, task_row=None, ssh_rows=None):
    summary, cards = [], []
    labels = ("Commande en clair", "Commande encodée")
    for label, row in zip(labels, rows):
        rule, agent = row["rule"], row["agent"]
        command = row["data"]["win"]["eventdata"]["commandLine"]
        utc = datetime.fromisoformat(row["timestamp"]).astimezone(timezone.utc).isoformat()
        mitre = ", ".join(rule.get("mitre", {}).get("id", [])) or "Non renseigné"
        summary.append(f'<tr><td>{text(label)}</td><td>{text(rule["id"])}</td><td>{text(rule["level"])}</td><td>{text(utc)}</td></tr>')
        decoded = decoded_script(command)
        extra = f'<h3>Texte décodé localement — jamais exécuté</h3><pre>{text(decoded)}</pre>' if decoded is not None else ""
        cards.append(f'''<section><h2>{text(label)}</h2>
<dl><dt>Machine</dt><dd>{text(agent['name'])} · agent {text(agent['id'])} · {text(agent.get('ip', 'Non renseignée'))}</dd>
<dt>Règle native</dt><dd>{text(rule['id'])} · niveau {text(rule['level'])}</dd>
<dt>Description originale</dt><dd>{text(rule['description'])}</dd>
<dt>MITRE ATT&amp;CK</dt><dd>{text(mitre)}</dd>
<dt>Heure de l’alerte (UTC)</dt><dd>{text(utc)}</dd>
<dt>Identifiant de l’alerte</dt><dd>{text(row.get('id', 'Non renseigné'))}</dd></dl>
<h3>Commande enregistrée</h3><pre>{text(command)}</pre>{extra}</section>''')
    return '''<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>SOC Lab V2 — rapport des scénarios</title><style>
*{box-sizing:border-box}body{margin:0;background:#eef2f6;color:#172b40;font:16px/1.6 system-ui,sans-serif}
main{max-width:1050px;margin:auto;padding:36px 22px}h1{font-size:32px;line-height:1.2}h2{font-size:23px}h3{font-size:16px}
.eyebrow{color:#285f83;font-weight:700;letter-spacing:1px}.notice{background:#fff2cc;border-left:5px solid #bd8200;padding:18px}
section{background:white;border:1px solid #d4dde5;border-radius:10px;padding:24px;margin:22px 0}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:12px;border-bottom:1px solid #d4dde5}
.table-wrap{overflow:auto}dt{font-weight:700}dd{margin:0 0 12px;overflow-wrap:anywhere}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#102a3d;color:#e5f0f6;padding:16px;border-radius:6px;font-size:13px}
footer{font-size:14px;color:#526678}li{margin-bottom:9px}@media print{body{background:white}main{padding:0}section{break-inside:avoid}pre{color:black;background:#eee}}
</style></head><body><main><p class="eyebrow">HOME SOC LAB · V2 · RAPPORT LOCAL</p>
<h1>Scénarios Windows et SSH sur Ubuntu</h1>
<p class="notice"><strong>Simulations inoffensives de laboratoire.</strong> Les scripts PowerShell affichent un marqueur de test et les commandes de découverte consultent le système. Ces alertes ne constituent pas des incidents confirmés. Le niveau Wazuh indique une priorité, pas une probabilité de compromission.</p>
<section><h2>Comparaison PowerShell : résultats observés</h2><p>Deux alertes sélectionnées, issues d’un même laboratoire. Le rapport présente les observations conservées dans les exports.</p>
<div class="table-wrap"><table><thead><tr><th>Test</th><th>Règle</th><th>Niveau</th><th>Heure UTC</th></tr></thead><tbody>''' + "".join(summary) + '''</tbody></table></div></section>''' + "".join(cards) + '''
''' + render_correlations(correlations) + render_task(task_row) + render_ssh(ssh_rows) + '''<section><h2>Vérifications proposées à l’analyste</h2><ul>
<li>Identifier l’utilisateur, le processus parent et le contexte de lancement.</li>
<li>Examiner la commande et, si elle est encodée, lire son texte décodé sans l’exécuter.</li>
<li>Comparer avec les événements PowerShell 4104 et les événements voisins disponibles.</li>
<li>Confirmer si l’activité était attendue avant de décider d’une investigation supplémentaire.</li></ul></section>
<section><h2>Portée et limites</h2><p>Dans ce test, PowerShell lance une autre instance PowerShell. La règle 92057 décrit ce contexte avec une commande Base64. Le résultat ne démontre pas la détection de toutes les formes de PowerShell encodé.</p>
<p>Les exports d’alertes n’ont pas de full_log ; les sources correspondantes sont conservées séparément dans powershell-comparison.archives.jsonl. Un validateur distinct contrôle leur cohérence. Ce rapport n’effectue ni validation par le moteur Wazuh, ni mesure de couverture, ni décision de réponse automatique.</p>
<p>Les heures affichées sont en UTC. Les commandes sont affichées telles que stockées, avec leurs caractères d’échappement éventuels. Des saturations du tampon de l’agent ont été observées pendant le laboratoire ; l’exhaustivité de la collecte n’est pas garantie.</p></section>
<footer>Généré localement par Python à partir d’exports JSONL sélectionnés. Aucune requête réseau ni service d’IA utilisé.</footer>
</main></body></html>'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        rows = [read_alert(args.evidence / n) for n in ("powershell-plain.alerts.jsonl", "powershell-encoded.alerts.jsonl")]
        if [r["rule"]["id"] for r in rows] != ["92027", "92057"]:
            raise ValueError("unexpected comparison rule IDs")
        cases = read_correlations(args.evidence)
        task_row = read_task(args.evidence)
        ssh_rows = ssh(args.evidence)
        document = render(rows, cases, task_row, ssh_rows)
        with args.output.open("x", encoding="utf-8") as handle:
            handle.write(document)
        print("Rapport créé :", args.output.resolve())
        print("PowerShell, 4 essais de corrélation, création de tâche et 8 échecs SSH présentés. Aucun incident confirmé.")
        return 0
    except (OSError, ValueError, KeyError, TypeError, ET.ParseError, AttributeError) as exc:
        print("Rapport non généré :", exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
