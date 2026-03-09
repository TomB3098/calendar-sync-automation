# Brand Guidelines - Webdesign Becker

Diese Markdown-Datei umfasst die vollständigen, extrahierten Design-Richtlinien (Styling-Vorgaben) basierend auf der aktuellen Implementierung im Projekt. Sie dient als Single Source of Truth für das Branding, UI-Komponenten, Hover-Effekte und Hintergrundstrukturen.

---

## 1. Typografie (Fonts)
Die Typografie ist über Google Fonts in `app/layout.tsx` definiert und nutzt CSS-Variablen.

- **Überschriften (Heading):** `Poppins` (Weights: 400, 500, 600, 700)
- **Fließtext (Body / Sans):** `Mulish` (Weights: 400, 500, 600, 700)

---

## 2. Farben (Colors)
Die zentrale Farbpalette ist in `globals.css` als CSS-Variablen (`:root`) angelegt.

### Hauptfarben (Brand)
- **Primary:** `#43a9d1` (Hellblau)
- **Secondary:** `#fc4349` (Rot/Koralle)

### Textfarben
- **Text Primary:** `#46515c` (Dunkles Schiefergrau)
- **Text Muted:** `#9aa7b5` (Grau-Blau)

### Hintergrundfarben (Backgrounds & Surfaces)
- **Background Default:** `#f7f8fb` (Sehr helles Graublau)
- **Background Alt:** `#edf1f4` (Etwas dunkleres Graublau)
- **Surface Dark 1:** `#2c3e50` (Dunkelblau)
- **Surface Dark 2:** `#384b5f` (Etwas helleres Dunkelblau)

### Transparenzen (Glassmorphism)
- **Glass Background:** `rgb(255 255 255 / 65%)` (Weiß, 65% Deckkraft)
- **Glass Border:** `rgb(255 255 255 / 50%)` (Weiß, 50% Deckkraft)

---

## 3. Hintergrundstrukturen (Background Structures)
Die Website nutzt komplexe, gestapelte Hintergründe (Gradients & Patterns) für visuelle Tiefe.

### Globaler Body Background
Der Standard-Hintergrund besteht aus mehreren Ebenen:
1. Ein sanfter radialer Verlauf (`circle at 10% 0%`) mit 15% Primary.
2. Ein radialer Verlauf (`circle at 90% 15%`) mit 12% Secondary.
3. Ein radialer Verlauf (`circle at 50% 100%`) mit 8% Primary.
4. Ein linearer Verlauf von oben nach unten (`#f8fbfd` (0%) -> `#f4f7fa` (60%) -> `#eef2f6` (100%)).

### Dotted Grid Pattern (`body::before`)
Ein feines Punktraster, das sich über die ganze Seite legt:
- **Opacity:** 0.25
- **Pattern:** Radiales Gradientenmuster (`rgb(34 38 54 / 18%) 0.8px`, transparent 0.8px) bei einer Größe von `3px 3px`.
- **Maske:** Das Raster wird weich über eine Maske verblendet (oben und unten transparent auslaufend).

### Surface Alt (`.surface-alt`)
Ein leicht farbiger Oberflächenstil, bestehend aus:
- 10% Primary (Linear, 135deg)
- 9% Secondary (Linear, 225deg)
- Überlagert über `var(--color-bg-alt)`.

---

## 4. Spacing, Border Radius & Panels
Die grundlegenden Rundungen von Elementen:

- **Radius Small:** `4px` (`var(--radius-sm)`)
- **Radius Medium:** `5px` (`var(--radius-md)`)
- **Radius X-Large:** `20px` (`var(--radius-xl)`)
- **Pillen-Form (Buttons):** `9999px` (vollständig gerundet)

### Glass Panel (`.glass-panel`)
Dient für schwebende UI-Elemente:
- Hintergrund: 65% Weiß (`var(--color-glass-bg)`)
- Unschärfe (Backdrop Filter): `blur(16px)`
- Rahmen: 50% Weiß (`var(--color-glass-border)`)

### Neo Card (`.neo-card`)
Auffälligere Glass/Neuromorphic-Cards:
- Hintergrund: 65% Weiß
- Unschärfe: `blur(12px)`
- Besonderheit: Ein zusätzlicher linearer Gradienten-Maskeneffekt (`border: 1px solid rgb(255 255 255 / 80%)`) gibt dem Rand eine Glanzlicht-Reflexion.

---

## 5. Spotting-Styling & Schatten (Glows & Shadows)

### Typografie Gradients
- **`.text-gradient`**: Ein linearer Textverlauf von Primary (`#43a9d1`) zu Secondary (`#fc4349`).
- **`.text-gradient-subtle`**: Ein weicher Textverlauf von Surface Dark 1 (`#2c3e50`) zu Primary (`#43a9d1`).

### Soft Glow (`.soft-glow`)
Ein starker, weicher Glow-Schatten für Highlights:
- Äußerer Schatten: `0 30px 60px -20px rgb(67 169 209 / 15%)` (Primary, 15%)
- Innerer Schatten: `inset 0 1px 0 rgb(255 255 255 / 90%)` (Helles Top-Edge-Highlight)

### Animated Conic Gradient Border (`.pricing-glow-border`)
Ein rotierender RGB-ähnlicher Rand um spezielle Elemente (Pricing Tables):
- Nutzt einen CSS `@property --border-angle`.
- Hintergrund-Rahmen (`::before`) mit einem `conic-gradient(from var(--border-angle), transparent, Primary, Secondary, transparent)`.

---

## 6. Buttons & Hover-Styling (Interactions & States)

### Button System
- **`.btn-primary`**:
  - Gradient Background: Primary zu Secondary.
  - Form: Pill-Form (`border-radius: 9999px`), zentriert.
  - **Hover-State:** Aufhellung um 10% (`filter: brightness(1.1)`).
- **`.btn-secondary`**:
  - Hintergrund: Weiß mit 80% Deckkraft und `blur(16px)`.
  - Border: Helles Graublau (`rgb(226 232 240)`).
  - Textfarbe: Dunkelblau (`var(--color-surface-dark-1)`).
  - **Hover-State:** 
    - Text hebt sich (`transform: translateY(-2px)`).
    - Border wird hellblau (`rgb(67 169 209 / 0.4)`).
    - Hintergrund wird vollflächig Weiß.
    - Sanfter Schatten (`box-shadow: 0 4px 14px 0 rgb(0 0 0 / 0.05)`).
- **`.btn-secondary-dark`**:
  - (Für dunkle Container): Hintergrund Weiß 5%, Border Weiß 20%, `blur(16px)`.
  - **Hover-State:** Hintergrund Weiß 15%, Border Weiß 30%, `transform: translateY(-2px)`.

### Lift Hover (`.lift-hover`)
Globale Klasse, um Karten oder Elemente interaktiv wirken zu lassen:
- **Hover-State:**
  - Versatz nach oben und Skalierung: `transform: translateY(-6px) scale(1.01)`.
  - Starker Schatten entsteht (Primary, 20%): `box-shadow: 0 40px 70px -20px rgb(67 169 209 / 20%)`.
  - Border wechselt leicht ins Rötliche (Secondary, 30%): `border-color: rgb(252 67 73 / 30%)`.

### Pricing Hover (`.pricing-hover`)
Spezieller Hover für Preistabellen zur Vermeidung von Layout Shifts:
- Das Element startet mit einem unsichtbaren Inset-Shadow.
- **Hover-State:** Äußerer Drop-Shadow (Primary, 20%) und innerer Inset-Shadow/Rand in Rot (Secondary, 30%).

---

## 7. Spezielle Effekte & Animationen (Micro-Interaktionen)

- **Hero Price Pulse (`.hero-price-pulse`)**: Ein pulsierender Ring-Effekt. Es entstehen um das Element herum zwei absolute Pseudo-Elemente (`::before`, `::after`), welche skalieren und an Opazität verlieren.
  - Ring 1: Bläulich (Primary, 45%).
  - Ring 2: Rötlich (Secondary, 28% mit 1.2s Verzögerung).
- **Marquee Tracks (`.marquee-track`)**: Globale "Laufband"-Animation (linear, 34s Laufzeit).
- **Hero Ring Drift (`.hero-ring`)**: Ein unregelmäßig rotierender Ring im Hero Banner (`rotate` und leichtes `scale(1.04)` während der Drehung).
- **Siegel-Animationen (z. B. Hosting oder Vitals Seal)**: Verschiedene Seal Badges (z.B. `.hosting-seal-badge`, `.vitals-seal-badge`) setzen auf:
  - Sanftes Pochen ("Breathe"-Animation, Opacity & Scale Wechsel).
  - Unschärfeeinblendungen ("Color Float"-Animation, bewegte blur(15px) Kreise).
  - Balken-Animationen ("Bar Rise", simulierte Ladebalken für Performance Metrics).
- **Animated Gradient Text (`.animated-gradient-text`)**: Spezieller animierter Textverlauf, konfigurierbar (Horizontal, Vertical, Yoyo) und pausierbar auf Hover (`pause-on-hover`).
- **Lutzer Complex Gradient (`.bg-lutzer-complex-gradient`)**: Eine Hintergrund-Animation, bei der Tints zwischen `#ffffff` und leichten roten Facetten sanft (über 8 Sekunden) pulsieren.
