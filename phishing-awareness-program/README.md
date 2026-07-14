# PhishGuard — Phishing Awareness Training

An interactive, browser-based training module that teaches people how to
recognise and avoid phishing attacks. Built with plain HTML, CSS, and
JavaScript, so it runs by simply opening a file. No build step, no server, no
dependencies.

## What it covers

| Section | What the learner does |
|---------|-----------------------|
| **Welcome** | Why phishing matters, with animated statistics |
| **Your Inbox** | Click the red flags hidden in a live sample phishing email and learn what each one reveals |
| **Login Pages** | Compare a genuine and a fake Google login side by side, and learn to read a URL correctly |
| **Fake Websites** | Play a "safe or phishing?" domain-spotting game covering typosquatting, homoglyphs, and subdomain tricks |
| **The Human Factor** | Explore the six social-engineering levers (urgency, authority, greed, trust, curiosity, helpfulness) with the defence for each |
| **Daily Habits** | A checkable list of practical security tips (MFA, password managers, verifying requests, and more) |
| **Real Breaches** | Four real case studies: the $100M Google/Facebook scam, the Twitter Bitcoin takeover, the RSA SecurID breach, and Colonial Pipeline |
| **Knowledge Check** | A scored 10-question quiz with instant feedback and explanations. 8/10 to pass |

Progress through the sections is tracked in the sidebar.

## Running it

Just open **`index.html`** in any modern browser. That's it.

```
# Windows
start index.html

# macOS
open index.html

# or drag index.html onto a browser window
```

> The Google Fonts are loaded from the web for the nicest typography. Without
> an internet connection the module still works perfectly; it simply falls back
> to your system fonts.

## Project structure

```
phishing-awareness-program/
├── index.html          # the training module (structure + content)
├── css/
│   └── styles.css      # all styling, light + dark aware
├── js/
│   ├── content.js      # educational data: email flags, tactics, tips, cases, domains
│   ├── quiz.js         # the 10-question quiz bank
│   └── app.js          # navigation, progress, and all interactive behaviour
└── README.md
```

To edit the content (add a tip, a case study, or a quiz question), you only need
to touch the data arrays in `js/content.js` and `js/quiz.js`. The interface
rebuilds itself from that data.

## Design notes

- **Light and dark themes** are both supported automatically via
  `prefers-color-scheme`.
- **Responsive**: the sidebar collapses into a menu button on narrow screens.
- **Accessible motion**: animations respect `prefers-reduced-motion`.
- Typography pairs **Newsreader** (headings) with **IBM Plex Sans** (body) and
  **IBM Plex Mono** (URLs and code), for a trustworthy, technical feel.

## Educational scope

All examples, statistics, and case studies are drawn from well-documented,
real-world phishing incidents and industry reporting, and are used here purely
for training. The sample phishing email and fake login pages are simulated and
non-functional.
