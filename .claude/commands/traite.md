---
description: Lance l'orchestrateur (boucle code → test → review) sur une tâche décrite en langage naturel
argument-hint: "[--fg] [--resume <branche> | --here] <description>"
---

Tu vas lancer l'orchestrateur autonome `orchestrator.py` sur la tâche suivante, décrite par l'utilisateur :

<tâche>
$ARGUMENTS
</tâche>

**Détecte d'abord les flags en tête de `$ARGUMENTS`, retire-les, et garde le reste comme
description de la tâche.** Plusieurs peuvent se combiner :

- `--fg` (ou `--foreground`) → **mode avant-plan** (sinon : arrière-plan, défaut).
- `--resume <branche>` → **reprise isolée** : l'orchestrateur attache un worktree à une branche
  EXISTANTE et recharge ses findings ouverts. (Mode nouvelle tâche si absent.)
- `--here` → **reprise dans le checkout courant** (la branche sur laquelle l'utilisateur est déjà),
  sans worktree. Exclusif avec `--resume`.

Ce qui reste après avoir retiré les flags est la vraie description de la tâche, à utiliser partout
ci-dessous. En reprise (`--resume`/`--here`), **la description est facultative** : si l'utilisateur
n'en fournit pas, ne passe simplement PAS `--task-file` / `--desc` — l'orchestrateur recharge tout
seul la description originale (depuis `tasks.json`) ET les findings ouverts de la branche. Ne fournis
une description que si l'utilisateur en donne une (elle complète/oriente la reprise).

Décide toi-même de tout ce qui peut l'être, sans poser de question inutile. Procède ainsi :

1. **Vérifie le contexte.** Le répertoire courant doit être la racine d'un dépôt git
   (`git rev-parse --show-toplevel`). Sinon, signale-le et arrête.

2. **Choisis un nom de tâche `<slug>`** (kebab-case court) :
   - **nouvelle tâche** : résume la description (ex. « ajoute une favicon » → `favicon`) ;
     il nommera la branche `feat/<slug>`.
   - **`--resume <branche>`** : dérive le slug de la branche (retire le préfixe `feat/`).
     Vérifie au préalable que la branche existe (`git rev-parse --verify <branche>`) et qu'elle
     n'est PAS checkout ailleurs ; si elle l'est, conseille `--here` à la place.
   - **`--here`** : le slug sert juste au nommage des logs ; vérifie que l'utilisateur n'est pas
     sur la branche par défaut (`main`/`master`) — si si, préviens-le (il édite son arbre réel).

3. **Détermine la commande de tests** en inspectant le dépôt :
   - Python → `pytest -q` (si `pyproject.toml` / `pytest.ini` / dossier `tests/`)
   - Node → le script `test` du `package.json` (souvent `npm test`)
   - Go → `go test ./...`  |  Rust → `cargo test`
   - Si rien de pertinent n'est trouvé, utilise `true` (on ne valide alors que sur la review)
     et **préviens l'utilisateur** de ce choix.
   - Si l'utilisateur a précisé une commande de tests dans sa description, respecte-la.

4. **Si une description est fournie**, écris-la dans un fichier temporaire (pour éviter tout souci
   d'échappement), sans les flags :

   ```bash
   printf '%s' "<description sans les flags>" > /tmp/orchestrator-<slug>.txt
   ```
   Si la description est vide (reprise sans texte), **n'écris rien** et n'utilise pas `--task-file`.

5. **Lance l'orchestrateur.** Construis la commande en ajoutant l'option de reprise du mode détecté
   (`--resume <branche>`, `--here`, ou rien pour une nouvelle tâche), et `--task-file` UNIQUEMENT si
   une description a été fournie :

   ```bash
   python3 /home/ftriquet/Documents/AI-Job/orchestrator.py <slug> \
       --test-cmd "<commande de tests>" --max-iter 3 \
       [--resume <branche> | --here] \
       [--task-file /tmp/orchestrator-<slug>.txt]   # omis si reprise sans description
   ```

   Puis selon le mode d'exécution :

   - **Arrière-plan (DÉFAUT)** — une exécution peut dépasser 10 minutes, donc on ne bloque pas la
     session. Redirige la sortie vers un log (`> /tmp/orchestrator-<slug>.out 2>&1`) et lance avec
     `run_in_background: true`. Puis **relaie la progression** (étape 6).

   - **Avant-plan (`--fg`)** — lance la MÊME commande **sans** `run_in_background`, avec un timeout
     proche du maximum (600000 ms). La sortie s'affiche directement. ⚠️ Préviens que l'outil Bash
     **coupe à 10 minutes** : si le job risque d'être plus long, conseille `--max-iter 1` ou de
     lancer le script dans un terminal. En avant-plan, saute l'étape 6 et passe au résumé.

6. **Relaie la progression pendant le run (mode arrière-plan, IMPORTANT).** Ne reste pas silencieux
   jusqu'à la fin : l'utilisateur veut suivre l'avancement. Surveille la sortie du job (le fichier
   `/tmp/orchestrator-<slug>.out` et/ou la sortie de la tâche en arrière-plan) et **reposte
   régulièrement** (toutes les ~30-60 s, ou à chaque nouvelle étape) les nouvelles lignes
   d'activité au format de l'orchestrateur :
   - les changements d'itération (`──── Itération N/M ────`),
   - le flux des sessions (`[codeur] 🔧 …`, `[reviewer] 💬 …`, `✓ session terminée (Xs, $Y)`),
   - le résultat des tests et de la review (OK / KO + reboucle).

   Pour cela, après le lancement, relis périodiquement le delta du log (par ex. via l'outil de
   monitoring ou en relisant la sortie de la tâche), jusqu'à ce que le process se termine.
   Préviens que c'est par à-coups (pas du temps réel), et que pour un flux strictement live
   l'utilisateur peut aussi `tail -f /tmp/orchestrator-<slug>.out` dans son propre terminal.

7. **Restitue à la fin.** Quand le job se termine, résume :
   - succès ✅ ou échec ❌ (et pourquoi) ;
   - la branche concernée (`feat/<slug>` pour une nouvelle tâche, la branche reprise sinon) et
     comment l'inspecter (`git checkout <branche>`) ;
   - les findings du reviewer (lis `.orchestrator/findings.jsonl`) ;
   - les **découvertes hors-périmètre** s'il y en a (lis `.orchestrator/discoveries.jsonl`) —
     signale-les comme dette à traiter plus tard ;
   - si le job a échoué au garde-fou, propose de **reprendre** : `--resume <branche>` (si l'utilisateur
     n'est pas dessus) ou `--here` (s'il bascule sur la branche).
   - les transcriptions archivées dans `.orchestrator/logs/` en cas de besoin.

Rappels :
- L'orchestrateur tourne en `--dangerously-skip-permissions`. En mode worktree (nouvelle tâche ou
  `--resume`) c'est isolé et jetable ; en `--here` il édite **directement le checkout courant**
  (préviens-en l'utilisateur). Rien n'est poussé.
- Démarre avec `--max-iter 3` pour limiter le coût ; relance avec plus si l'utilisateur le demande.
- Pense à ce que `.orchestrator/` soit dans le `.gitignore` du projet cible.
