# Anleitung M8: CI-Pipeline – dein Teil

> Für: Manuel · Stand: 19.10.2026 · Branch: `ci/m8-pipeline`
> Dauer: etwa 1–2 Stunden

Die Pipeline steht in [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml).
Fertig sind die Jobs **Secret-Scan**, **SBOM**, **SAST**, **Tests** und das **Quality Gate**
([`scripts/quality_gate.py`](../../scripts/quality_gate.py)). Dein Teil:

| Teil | Was | Wo |
|---|---|---|
| A | Sicherheitseinstellungen für GitHub Actions setzen | GitHub-Weboberfläche |
| B | Ersten Lauf auslösen und sehen, dass das Gate **abbricht** | GitHub Desktop, Actions-Tab |
| C | Den **SCA-Job** selbst schreiben | `ci.yml`, Job `sca` |
| D | Zweiten Lauf auswerten und Evidence sichern | Actions-Tab, Ordner `evidence/` |
| E | (in 3 Tagen) Quality Gate als Pflicht-Check eintragen | Branch-Schutz |

---

## So funktioniert die Pipeline

```
secrets ─┐
sbom ────┤
sast ────┼──> quality-gate
sca  ────┤
test ────┘
```

- Die fünf Scan-Jobs laufen **parallel** und brechen **nicht** selbst ab. Sie schreiben
  nur Berichte (JSON) und laden sie als Artefakt `reports-<job>` hoch.
- Der Job **Quality Gate** lädt alle Artefakte herunter und lässt `quality_gate.py`
  entscheiden. Abbruch bei: Secret gefunden, Schwachstelle HIGH/CRITICAL oder
  CVSS ≥ 7.0, Semgrep ERROR, Bandit HIGH, leere SBOM, fehlgeschlagene Tests –
  **und wenn ein Bericht fehlt** („fail-closed“).
- Vorteil: Es gibt genau **einen** Status-Check („Quality Gate“), den wir später im
  Branch-Schutz als Pflicht eintragen.

**Warum fail-closed?** Beim Bauen ist uns zweimal passiert, dass ein Scanner unsere
Lockfiles nicht erkannt hat und deshalb nichts geprüft hat – mit „0 Schwachstellen“ als
Ergebnis. Ein Scan, der still nichts tut, sieht genauso grün aus wie ein sauberer Scan.
Deshalb prüft das Gate auch, ob überhaupt Pakete gefunden wurden. (Das ist ein guter
Punkt für die Doku, Kapitel „Lessons Learned“.)

---

## Teil A – Sicherheitseinstellungen für Actions (10 min)

Auf GitHub im Repo: **Settings → Actions → General**

1. **Actions permissions:** „Allow Manujpg, and select non-Manujpg, actions and reusable
   workflows“ wählen, dann nur **„Allow actions created by GitHub“** anhaken.
   Alle anderen Haken aus, das Textfeld leer lassen.
   → Wir nutzen nur `actions/checkout`, `actions/setup-python`, `actions/upload-artifact`,
   `actions/download-artifact`. Alle Scanner laufen als Docker-Images. Eine kompromittierte
   Fremd-Action (wie 2025 bei `tj-actions/changed-files`) könnte so gar nicht erst laufen.
2. **Workflow permissions:** „Read repository contents and packages permissions“ wählen.
   Den Haken „Allow GitHub Actions to create and approve pull requests“ **entfernen**.
   → Das automatische Token der Pipeline darf nur lesen (Least Privilege). Wenn M9 in die
   Registry pushen muss, geben wir das gezielt nur diesem einen Job.
3. **Fork pull request workflows:** Standard lassen („Require approval for first-time
   contributors“).
4. Speichern.

Mach von beiden Abschnitten einen Screenshot für die Doku (Ordner `docs/screenshots/`).

---

## Teil B – Erster Lauf: das Gate muss abbrechen (10 min)

Der SCA-Job ist absichtlich noch leer. Genau deshalb lohnt sich ein Lauf **vorher**:
Er beweist, dass das Gate bei fehlenden Berichten abbricht.

1. GitHub Desktop: Du bist auf Branch `ci/m8-pipeline`. Alle Änderungen committen:
   ```
   ci: Pipeline mit Secret-Scan, SBOM, SAST, Tests und Quality Gate (M8)
   ```
2. **Publish branch**, dann **Create Pull Request** (Ziel `main`).
   Hinweis: Der PR zeigt auch den Commit aus PR #2 (M3/M4), weil der Branch darauf
   aufbaut. Sobald Laszlo PR #2 mergt, verschwindet der aus der Ansicht.
3. Im PR unten bzw. im Tab **Actions** den Lauf öffnen. Erwartung:
   - `Secret-Scan`, `SBOM`, `SAST`, `Lint und Tests` grün
   - `SCA` grün (er tut ja nichts)
   - **`Quality Gate` rot** mit „Bericht fehlt: trivy-fs.json“ und „Bericht fehlt: pip-audit.json“
4. Im Lauf ganz oben auf **Summary** klicken: Dort steht die Tabelle des Gates.
   Screenshot machen – das ist ein starker Nachweis für die Präsentation.

---

## Teil C – Den SCA-Job schreiben (30–60 min)

SCA = Software Composition Analysis: Wir prüfen nicht unseren Code, sondern die
**Abhängigkeiten** (FastAPI, SQLAlchemy, …) auf bekannte Schwachstellen (CVEs).
Wir nutzen zwei Werkzeuge:

| Werkzeug | Liefert | Rolle im Gate |
|---|---|---|
| **Trivy** | Schwachstellen **mit Severity und CVSS** | entscheidet über Abbruch (CVSS ≥ 7.0) |
| **pip-audit** | Schwachstellen aus der Python-Advisory-Datenbank, **ohne** CVSS | zweite Meinung, nur Warnung |

Öffne `.github/workflows/ci.yml` und such den Job `sca:`. Dort stehen drei `TODO`s.
Schau dir zur Orientierung die Jobs `sbom` und `sast` direkt darüber an – dein Job
funktioniert nach demselben Muster.

### Schritt 1: Trivy

Füge nach „Berichtsordner anlegen“ einen Schritt ein, der Trivy als Container startet.
Bausteine:

- Image: die Variable `$TRIVY_IMAGE` (steht oben im Workflow unter `env:`)
- Den Repo-Ordner **nur lesend** einhängen und `reports/` beschreibbar,
  so wie beim Syft-Schritt: `-v "$PWD:/src:ro" -v "$PWD/reports:/out"`
- Trivy-Befehl: `fs` (Dateisystem-Scan) auf `/src/backend`
- Diese Optionen brauchst du – überleg bei jeder, warum:

| Option | Bedeutung |
|---|---|
| `--scanners vuln` | nur Schwachstellen (Secrets macht Gitleaks, Konfiguration kommt in M9) |
| `--list-all-pkgs` | alle gefundenen Pakete in den Bericht schreiben – **das Gate prüft, ob Pakete erkannt wurden** |
| `--format json --output /out/trivy-fs.json` | Bericht als JSON in `reports/` |
| `--exit-code 0` | Trivy bricht nicht selbst ab, das Gate entscheidet |
| `--quiet` | weniger Log-Ausgabe |

Trivy erkennt `backend/requirements.txt` automatisch (darum haben wir die Lockfiles
von `.lock` auf `.txt` umbenannt).

### Schritt 2: pip-audit

1. Python einrichten – kopier dafür den `actions/setup-python`-Schritt aus dem Job `sast`
   **inklusive** Commit-SHA und Kommentar. Niemals `@v7` statt SHA schreiben: Ein Tag kann
   umgehängt werden, ein Commit-SHA nicht.
2. pip-audit installieren: Es steckt schon in `backend/requirements-dev.txt`. Installiere
   genauso wie im Job `sast` (`--require-hashes --no-deps`).
3. pip-audit gegen **`backend/requirements.txt`** laufen lassen (das sind die Pakete, die
   wirklich im Image landen). Optionen:

| Option | Bedeutung |
|---|---|
| `-r backend/requirements.txt` | diese Datei prüfen |
| `--require-hashes --disable-pip` | nicht neu auflösen, sondern exakt die gepinnten Versionen prüfen |
| `--strict` | Fehler beim Auflösen sind Fehler, nicht still ignoriert |
| `-f json -o reports/pip-audit.json` | Bericht als JSON |

**Achtung:** pip-audit beendet sich mit Exit-Code 1, **sobald es eine Schwachstelle
findet**. Dann bricht der Schritt ab und der Upload danach läuft nicht. Löse das so,
dass der Job trotzdem weiterläuft. Überleg dir dabei: Was passiert, wenn pip-audit
wegen eines **echten Fehlers** abbricht und gar keinen Bericht schreibt? (Tipp: Was macht
das Gate mit fehlenden Berichten?)

### Schritt 3: Upload

Kopier den `upload-artifact`-Schritt aus `sast` und ändere den Namen auf **`reports-sca`**.
`if-no-files-found: error` bleibt drin.

### Lokal prüfen, bevor du pushst

Syntaxprüfung des Workflows (Git Bash im Repo-Ordner):

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W):/repo:ro" -w /repo rhysd/actionlint:latest -no-color
```

Keine Ausgabe = keine Fehler. Danach den Trivy-Befehl einmal lokal ausprobieren
(ersetze `<DEIN-BEFEHL>` durch deine Trivy-Optionen):

```bash
mkdir -p /tmp/rep && MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W):/src:ro" -v "$(cygpath -w /tmp/rep):/out" aquasec/trivy:0.76.0 <DEIN-BEFEHL>
```

Wenn du fertig bist, sag mir Bescheid – ich schaue mir deinen Job an, bevor du pushst.

<details>
<summary>Lösung zum Vergleich (erst aufklappen, wenn du fertig bist)</summary>

```yaml
      - name: Trivy (Abhängigkeiten)
        run: |
          docker run --rm -v "$PWD:/src:ro" -v "$PWD/reports:/out" "$TRIVY_IMAGE" \
            fs /src/backend \
              --scanners vuln --list-all-pkgs \
              --format json --output /out/trivy-fs.json \
              --exit-code 0 --quiet

      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: ${{ env.PYTHON_VERSION }}

      - name: pip-audit
        run: |
          python -m pip install --require-hashes --no-deps -r backend/requirements-dev.txt
          # Exit 1 bei Funden ist erwartet; das Gate entscheidet. Schreibt pip-audit wegen
          # eines echten Fehlers keinen Bericht, bricht das Gate ab ("Bericht fehlt").
          pip-audit -r backend/requirements.txt --require-hashes --disable-pip --strict \
            -f json -o reports/pip-audit.json || echo "pip-audit meldet Funde oder Fehler"

      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        with:
          name: reports-sca
          path: reports/
          retention-days: 90
          if-no-files-found: error
```

</details>

---

## Teil D – Zweiter Lauf und Evidence sichern (15 min)

1. Commit, z. B. `ci: SCA-Job mit Trivy und pip-audit`, und **Push origin**.
   Der PR startet automatisch einen neuen Lauf. Erwartung: alles grün, Gate **bestanden**.
2. Im Lauf unter **Artifacts** das Paket **`evidence-backend-run-<Nummer>-1`** herunterladen.
3. Entpacken. Darin ist der Ordner `backend/` mit `run/`, `sast/`, `sbom/`, `sca/`, `secrets/`.
4. Den **Inhalt** davon nach `evidence/backend/` im Repo kopieren (Ordner zusammenführen,
   nichts überschreiben – jeder Lauf hat ein eigenes Präfix `run-<Nummer>-1-…`).
   Mach das auch für den **roten Lauf aus Teil B**: Auch fehlgeschlagene Läufe sind Nachweise.
5. Commit: `chore(evidence): Berichte der Läufe <Nr. B> und <Nr. D>`.

Ab M9 erledigt die Pipeline das Ablegen selbst. Bis dahin ist es Handarbeit.

---

## Teil E – In 3 Tagen: Gate als Pflicht-Check

Sobald GitHub Pro aktiv ist (Branch-Schutz greift):

1. **Settings → Branches →** Regel für `main` bearbeiten.
2. Bei „Require status checks to pass before merging“ im Suchfeld **`Quality Gate`**
   eingeben und auswählen.
3. „Require branches to be up to date before merging“ anhaken.
4. Speichern. Ab jetzt kann niemand mehr mergen, wenn das Gate rot ist – auch du nicht.

---

## Wenn etwas schiefgeht

| Symptom | Ursache / Lösung |
|---|---|
| Job rot mit „The action … is not allowed“ | Teil A zu streng oder Tippfehler im SHA. Nur `actions/*` ist erlaubt. |
| SBOM-Job: „SBOM enthält keine Abhängigkeiten“ | Syft hat die Lockfiles nicht gefunden – Dateinamen prüfen. |
| Gate: „SCA hat keine Pakete erkannt“ | `--list-all-pkgs` fehlt oder Trivy scannt den falschen Ordner. |
| Gate: „Bericht fehlt: pip-audit.json“ | pip-audit ist abgebrochen, bevor es den Bericht schrieb – Log des SCA-Jobs lesen. |
| `Lint und Tests` rot | Lokal `cd backend && .venv/Scripts/python.exe -m pytest` ausführen. |
