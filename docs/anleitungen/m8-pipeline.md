# Anleitung M8: CI-Pipeline – dein Teil

> Für: Manuel · Stand: 19.10.2026 · Branch: `ci/m8-pipeline`
> Dauer: etwa 45 Minuten

Die Pipeline ist vollständig: [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml)
mit den Jobs **Secret-Scan**, **SBOM**, **SAST**, **SCA**, **Tests** und dem zentralen
**Quality Gate** ([`scripts/quality_gate.py`](../../scripts/quality_gate.py)). Dein Teil:

| Teil | Was | Wo |
|---|---|---|
| A | Sicherheitseinstellungen für GitHub Actions setzen | GitHub-Weboberfläche |
| B | Ersten Lauf auslösen und auswerten | GitHub Desktop, Actions-Tab |
| C | Verstehen, was die Jobs tun (für Doku und Präsentation) | diese Anleitung |
| D | Evidence ins Repo übernehmen | Ordner `evidence/` |
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
  CVSS ≥ 7.0, Semgrep ERROR, Bandit HIGH, SBOM ohne Abhängigkeiten, fehlgeschlagene
  Tests – **und wenn ein Bericht fehlt, leer ist oder nichts geprüft hat** („fail-closed“).
- Vorteil: Es gibt genau **einen** Status-Check („Quality Gate“), den wir im
  Branch-Schutz als Pflicht eintragen.
- Jeder Lauf erzeugt ein Artefakt `evidence-backend-run-<Nr>-<Versuch>` in genau der
  Ordnerstruktur, die die Aufgabe für `evidence/` verlangt.

**Warum fail-closed?** Beim Bauen haben Syft und Trivy unsere Lockfiles (damals
`requirements.lock`) nicht erkannt und deshalb nichts geprüft – mit „0 Schwachstellen“
als Ergebnis. Ein Scan, der still nichts tut, sieht genauso grün aus wie ein sauberer
Scan. Deshalb prüft das Gate auch, ob überhaupt Pakete gefunden wurden, und die Dateien
heißen jetzt `requirements.txt`. (Guter Punkt für „Lessons Learned“.)

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
3. **Fork pull request workflows:** Standard lassen.
4. Speichern.

Mach von beiden Abschnitten einen Screenshot für die Doku (Ordner `docs/screenshots/`).

---

## Teil B – Erster Lauf (15 min)

1. GitHub Desktop: Du bist auf Branch `ci/m8-pipeline`. Alle Änderungen committen:
   ```
   ci: Pipeline mit Secret-Scan, SBOM, SAST, SCA, Tests und Quality Gate (M8)
   ```
2. **Publish branch**, dann **Create Pull Request** (Ziel `main`).
   Hinweis: Der PR zeigt auch den Commit aus PR #2 (M3/M4), weil der Branch darauf
   aufbaut. Sobald Laszlo PR #2 mergt, verschwindet der aus der Ansicht.
3. Im PR unten bzw. im Tab **Actions** den Lauf öffnen. Erwartung: alle sechs Jobs grün,
   der erste Lauf dauert etwa 3–5 Minuten (Images werden geladen).
4. Im Lauf oben auf **Summary** klicken: Dort steht die Tabelle des Quality Gates mit
   Kennzahlen (Anzahl Pakete, Funde je Scanner, SBOM-Komponenten).
   **Screenshot machen** – das ist ein starker Nachweis für Doku und Präsentation.
5. Ist ein Job rot, schau in die Tabelle „Wenn etwas schiefgeht“ unten oder schick mir
   die Fehlermeldung.

---

## Teil C – Was die Jobs tun (zum Verstehen, 15 min lesen)

Diese Fragen kommen in der Präsentation garantiert. Lies den jeweiligen Job in
`ci.yml` parallel mit.

### Secret-Scan (Gitleaks)
- `fetch-depth: 0` holt die **gesamte** Git-Historie, nicht nur den letzten Commit.
  Ein Secret, das einmal committet und später gelöscht wurde, steckt weiter in der
  Historie und wird trotzdem gefunden.
- `--redact` sorgt dafür, dass ein gefundenes Secret nicht im Log oder Bericht landet.

### SBOM (Syft)
- Erzeugt eine **CycloneDX**-Stückliste aller Python-Pakete mit Version und Package-URL.
- Das ist die **Quell-SBOM**. In M9 kommt die **Image-SBOM** dazu, die zusätzlich die
  Alpine-Systempakete im Container enthält.

### SAST (Semgrep, Bandit)
- Semgrep mit den Regelsätzen `p/python` und `p/owasp-top-ten`, Bandit speziell für Python.
- Beide prüfen **unseren Code** (z. B. SQL-Injection, unsichere Zufallszahlen, `eval`).

### SCA (Trivy, pip-audit)
SCA prüft nicht unseren Code, sondern die **Abhängigkeiten** (FastAPI, SQLAlchemy, …)
auf bekannte Schwachstellen (CVEs).

| Werkzeug | Liefert | Rolle im Gate |
|---|---|---|
| **Trivy** | Schwachstellen **mit Severity und CVSS** | entscheidet über Abbruch (CVSS ≥ 7.0) |
| **pip-audit** | Schwachstellen aus der Python-Advisory-Datenbank, **ohne** CVSS | zweite Meinung, nur Warnung |

Wichtige Trivy-Optionen:

| Option | Bedeutung |
|---|---|
| `fs /src/backend` | Dateisystem-Scan, findet `requirements.txt` automatisch |
| `--scanners vuln` | nur Schwachstellen (Secrets macht Gitleaks) |
| `--list-all-pkgs` | alle Pakete in den Bericht – **das Gate prüft, ob Pakete erkannt wurden** |
| `--exit-code 0` | Trivy bricht nicht selbst ab, das Gate entscheidet |

Wichtige pip-audit-Optionen:

| Option | Bedeutung |
|---|---|
| `-r backend/requirements.txt` | nur die Pakete, die wirklich im Image landen |
| `--require-hashes --disable-pip` | exakt die gepinnten Versionen prüfen, nichts neu auflösen |
| `--strict` | Auflösungsfehler sind Fehler, nicht still ignoriert |
| `\|\| echo …` | pip-audit endet mit Exit 1, sobald es etwas findet. Damit der Bericht trotzdem hochgeladen wird, läuft der Job weiter. Bricht pip-audit wegen eines **echten** Fehlers ab, fehlt der Bericht – und das Gate bricht ab. |

### Lieferkette der Pipeline selbst
- Jede Action ist per **Commit-SHA** gepinnt (`@3d3c42e…  # v7.0.1`), nicht per Tag
  (`@v7`). Ein Tag kann umgehängt werden, ein Commit-SHA nicht.
- Jedes Scanner-Image ist per **Version und Digest** gepinnt.
- Python-Pakete werden nur mit **Hash-Prüfung** installiert (`--require-hashes`).

---

## Teil D – Evidence ins Repo übernehmen (10 min)

1. Im Lauf unter **Artifacts** das Paket **`evidence-backend-run-<Nr>-1`** herunterladen.
2. Entpacken. Darin ist der Ordner `backend/` mit `run/`, `sast/`, `sbom/`, `sca/`, `secrets/`.
3. Den **Inhalt** davon nach `evidence/backend/` im Repo kopieren (Ordner zusammenführen,
   nichts überschreiben – jeder Lauf hat ein eigenes Präfix `run-<Nr>-1-…`).
4. Commit: `chore(evidence): Berichte von Lauf <Nr>` und **Push origin**.
   Dieser Push löst übrigens den nächsten Lauf aus – so sammeln sich die Nachweise.

Ab M9 legt die Pipeline die Berichte selbst ab. Bis dahin ist es Handarbeit.

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
| Gate: „SBOM enthält keine Abhängigkeiten“ | Syft hat die Lockfiles nicht gefunden – Dateinamen prüfen. |
| Gate: „SCA hat keine Pakete erkannt“ | Trivy scannt den falschen Ordner oder `--list-all-pkgs` fehlt. |
| Gate: „Bericht fehlt: pip-audit.json“ | pip-audit ist abgebrochen, bevor es den Bericht schrieb – Log des SCA-Jobs lesen. |
| `Lint und Tests` rot | Lokal `cd backend && .venv/Scripts/python.exe -m pytest` ausführen. |
| Semgrep-Job hängt oder ist rot | Semgrep lädt die Regeln aus dem Internet; Lauf mit „Re-run jobs“ wiederholen. |
