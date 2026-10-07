# Designsystem „Lindle“ – PraxisTermin

> Stand: 02.10.2026 · Version 0.1.0
> Ziel: ein modernes, ruhiges und konsistentes Erscheinungsbild für die Terminbuchung der
> Ärztehaus Lindle mit minimalem Eigenaufwand im Frontend. Umgesetzt mit
> Tailwind CSS v4 (CSS-Variablen als Tokens) und shadcn/ui-Komponenten.

## 1. Referenzen und abgeleitete Prinzipien

Analysierte Referenzen (Oktober 2026): Doctolib (Design System „Oxygen“ und Buchungsflow),
Dr. Flex Booking-Widget, samedi White-Label-Buchung, Praxis-Websites praxis-wall36.de,
fennerpraxis.de, augen-venividi.de sowie kuratierte Beispielsammlungen für Praxis-Homepages.

Daraus abgeleitet:

1. **Ruhe statt Klinik.** Warm abgetöntes Off-White statt reinem Weiß, eine gedeckte
   Primärfarbe (Petrol statt „Medizinblau“), viel Weißraum, weiche Schatten.
2. **Vertrauen sichtbar machen.** Öffnungszeiten, Telefon und Notfallhinweis (116 117)
   immer erreichbar; Datenschutzhinweis direkt am Formular; Hinweis auf verschlüsselte Verbindung.
3. **Buchung als klarer Stepper.** Leistung → Ärzt:in → Termin (Kalender + Zeit-Chips) →
   Daten/Login → Bestätigung, mit Zusammenfassungskarte und Fortschrittsanzeige.
4. **Barrierefreiheit ist Pflicht (BFSG seit 28.06.2025, WCAG 2.1 AA).** Kontrast ≥ 4,5:1,
   Touchziele ≥ 44 px, sichtbare Fokusringe, Tastaturbedienbarkeit, Fehler als Text, nicht nur Farbe.
5. **Wenig Komponenten, konsequent genutzt.** Jede Seite baut aus denselben 15 Bausteinen.

## 2. Design-Tokens

Alle Tokens liegen in `frontend/src/styles/tokens.css` als CSS-Variablen und werden in
Tailwind v4 über `@theme` eingebunden. Niemals Hex-Werte direkt in Komponenten verwenden.

### Farben

| Token | Wert | Verwendung |
|---|---|---|
| `--color-primary-700` | `#1F4E5F` | Überschriften, Primär-Buttons, aktive Navigation |
| `--color-primary-500` | `#2F7A8C` | Links, Hover, Fokusring, Info |
| `--color-primary-100` | `#DCEDF0` | Ausgewählter Zeit-Slot, Info-Hintergrund, Badges |
| `--color-secondary-500` | `#7FA38A` (Salbei) | Illustrationen, sekundäre Flächen, Status „bestätigt“ |
| `--color-secondary-100` | `#E6EFE8` | Erfolgs-Hintergrund |
| `--color-accent-500` | `#E0A458` (Sand) | Sparsam: Hinweis-Badges, Highlight im Hero |
| `--color-neutral-0` | `#FFFFFF` | Karten, Eingabefelder |
| `--color-neutral-50` | `#F7F5F2` | Seitenhintergrund (Canvas) |
| `--color-neutral-100` | `#EEEBE6` | Trennflächen, Tabellenzeilen (zebra) |
| `--color-neutral-200` | `#DDD8D1` | Rahmen, Divider |
| `--color-neutral-500` | `#7A7570` | Sekundärtext (nur ≥ 16 px, Kontrast 4,6:1) |
| `--color-neutral-700` | `#4A4642` | Labels, Icons |
| `--color-neutral-900` | `#1E1C1A` | Fließtext |
| `--color-success` | `#2E7D5B` | Buchung bestätigt |
| `--color-warning` | `#B7791F` | Hinweise (z. B. „nur noch 2 Termine“) |
| `--color-error` | `#C0392B` | Validierungsfehler, Storno |
| `--color-info` | `#2F7A8C` | neutrale Hinweise |

Kontrastprüfung (WCAG): Primary-700 auf Neutral-50 ≈ 8:1, Weiß auf Primary-700 ≈ 7:1,
Neutral-900 auf Neutral-50 ≈ 15:1, Error auf Weiß ≈ 5,9:1.

### Typografie

| Token | Wert |
|---|---|
| `--font-heading` | `"Figtree", system-ui, sans-serif` (600/700) |
| `--font-body` | `"Inter", system-ui, sans-serif` (400/500/600) |
| Basis | 16 px, Zeilenhöhe 1,55 |
| Skala | `xs 12` · `sm 14` · `base 16` · `lg 18` · `xl 20` · `2xl 24` · `3xl 30` · `4xl 38` |

Fonts werden **lokal gebündelt** (kein Google-Fonts-CDN), damit die CSP ohne externe
Quellen auskommt und keine Nutzer-IPs an Dritte gehen.

### Form, Abstand, Tiefe

| Token | Wert |
|---|---|
| `--radius-sm` / `md` / `lg` / `pill` | 6 px / 12 px / 20 px / 999 px |
| Abstände | 4 · 8 · 12 · 16 · 24 · 32 · 48 · 64 px |
| `--shadow-sm` | `0 1px 2px rgba(31,78,95,.06)` |
| `--shadow-md` | `0 2px 4px rgba(31,78,95,.07), 0 8px 24px rgba(31,78,95,.08)` |
| `--touch-min` | 44 px (Buttons, Slot-Chips, Kalender-Tage) |
| Fokusring | 2 px `--color-primary-500` + 2 px Offset, nie entfernt |
| Container | max. 1120 px, Seitenränder 16 px (mobil) / 32 px (Desktop) |

## 3. Komponenteninventar (shadcn/ui-Basis)

| Komponente | Quelle | Einsatz |
|---|---|---|
| Button (primary / secondary / ghost / destructive) | shadcn | überall |
| Input, Textarea, Select, Checkbox, Switch | shadcn | Formulare |
| Form (react-hook-form + zod) mit Label, Description, Message | shadcn | Registrierung, Login, Buchung |
| Card | shadcn | Termin-Karten, Zusammenfassung, Dashboard-Kacheln |
| Calendar (Monatsansicht) | shadcn (react-day-picker) | Terminwahl |
| Badge | shadcn | Terminstatus, Rolle, MFA-Status |
| Dialog / AlertDialog | shadcn | Stornieren bestätigen, MFA-QR-Code |
| Sheet | shadcn | Mobile Navigation |
| Table | shadcn | Terminlisten Personal/Admin, Audit-Log |
| Tabs | shadcn | Dashboard-Bereiche |
| Toast (sonner) | shadcn | Erfolg/Fehler-Rückmeldung |
| Skeleton | shadcn | Ladezustände |
| **Stepper** | eigen (klein) | Fortschritt im Buchungsflow |
| **TimeSlotGrid** | eigen (klein) | Zeit-Chips (44 px, ausgewählt = primary-100 + Rahmen primary-700) |
| **AppShell** | eigen | Header mit Logo/Wortmarke, Navigation nach Rolle, Footer mit Kontakt/Notfall/Datenschutz |

Eigene Komponenten sind bewusst auf drei begrenzt.

## 4. Seiteninventar

| Route | Rolle | Inhalt |
|---|---|---|
| `/` | öffentlich | Hero (Claim, Primär-CTA „Termin buchen“), Öffnungszeiten, Leistungen, Team, Kontakt/Notfall |
| `/login`, `/register`, `/mfa` | öffentlich | Auth-Formulare, MFA-Code-Eingabe |
| `/buchen` | PATIENT | Stepper: Leistung → Ärzt:in → Termin → Prüfen & Buchen → Bestätigung |
| `/meine-termine` | PATIENT | Liste kommender/vergangener Termine, Stornieren |
| `/konto` | alle | Profil, Passwort, MFA ein-/ausschalten |
| `/praxis/termine` | STAFF, ADMIN | Tages-/Wochenliste, Suche, Anlegen/Verschieben/Stornieren |
| `/praxis/verfuegbarkeit` | STAFF, DOCTOR, ADMIN | Slots pflegen |
| `/arzt/heute` | DOCTOR | Tagesplan, Status setzen |
| `/admin/benutzer`, `/admin/aerzte`, `/admin/leistungen`, `/admin/audit` | ADMIN | Verwaltung |
| `/datenschutz`, `/impressum`, `/barrierefreiheit` | öffentlich | Pflichtseiten (fiktive Inhalte) |

## 5. Buchungsflow (Schrittfolge)

1. **Leistung wählen** – Karten mit Dauer (z. B. „Hausarztsprechstunde · 15 min“), Hinweis
   „Akute Beschwerden? Bitte anrufen oder 116 117“.
2. **Ärzt:in wählen** – Karten mit Name, Titel, Fachgebiet, Option „egal / nächster freier Termin“.
3. **Termin wählen** – Kalender (Tage mit freien Slots markiert, Text + Punkt), rechts Zeit-Chips.
4. **Prüfen & Buchen** – Zusammenfassungskarte, Versicherungsart, optionale Notiz (max. 200
   Zeichen, Zähler), Datenschutzhinweis, Button „Verbindlich buchen“. Nicht eingeloggt →
   Login/Registrierung inline, Flow-Zustand bleibt erhalten.
5. **Bestätigung** – Großer Erfolgszustand, Termin-Details, „Zu meinen Terminen“, ICS-Download.

## 6. Schreibstil und Sprache

Deutsch, Sie-Form, kurze Sätze, keine Fachbegriffe ohne Erklärung. Fehlermeldungen sagen,
was zu tun ist („Bitte geben Sie eine gültige E-Mail-Adresse ein“). Sicherheitsmeldungen
verraten nichts über Konten („E-Mail oder Passwort ungültig“).

## 7. Umsetzungsschritte Frontend

1. `npm create vite@latest frontend -- --template react-ts`, Tailwind v4, shadcn/ui init.
2. `tokens.css` mit obigen Variablen, `@theme` in `index.css`, Fonts lokal nach `public/fonts`.
3. AppShell + Stepper + TimeSlotGrid bauen, Rest aus shadcn generieren.
4. Seiten nach Inventar; API-Client mit TanStack Query, zod-Schemas aus Backend-OpenAPI ableiten.
5. Barrierefreiheits-Check mit axe DevTools und Tastatur-Durchlauf vor jedem Merge.
