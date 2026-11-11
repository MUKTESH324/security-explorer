# Security Explorer

Interactive, step-by-step walkthroughs of how attacks, protocols and defenses work. Each module plays out one scenario message by message:

- an animated network diagram, or the same exchange as a sequence diagram
- a plain-language explanation of every step, with a defender's note where it matters
- a packet table you can expand to see the actual request or payload
- defenses, plus CWE, OWASP, MITRE ATT&CK, MITRE ATLAS and RFC references linked automatically

The site has a home page, a filterable module catalog, curated learning paths, an About page and a search palette (`/` or `⌘K`).

## Run locally

Plain HTML, CSS and JavaScript: no build step and no dependencies. Serve the folder over HTTP:

```bash
python3 -m http.server 8000
```

Then open http://localhost:8000.

## Deploy for free

There's no build step: the repository root *is* the website.

1. Create an empty repository on GitHub, then push:
   ```bash
   git remote add origin https://github.com/<you>/security-explorer.git
   git push -u origin main
   ```
2. Pick one host:
   - **Vercel** (uses `vercel.json`): vercel.com → Add New → Project → import the repo → Framework preset "Other", leave the build command empty → Deploy.
   - **Netlify** (uses `netlify.toml`): app.netlify.com → Add new site → Import from Git → Deploy.
   - **GitHub Pages** (uses `.github/workflows/pages.yml`): repo Settings → Pages → Source: "GitHub Actions".

Every push to `main` redeploys automatically on all three.

### Security headers

The site ships with a strict Content-Security-Policy (no inline scripts, no third-party scripts; fonts from Google Fonts only), plus `nosniff`, `Referrer-Policy`, `Permissions-Policy`, HSTS and `frame-ancestors 'none'` on Vercel/Netlify. GitHub Pages can't set headers, so the CSP is also included as a `<meta>` tag in `index.html`. If you add an external script or image source, update the CSP in all three places.

## Project layout

| Path | What it is |
| --- | --- |
| `index.html` | Page shell: header, explorer, footer, search |
| `css/style.css` | All styles; light and dark themes via CSS variables |
| `js/config.js` | Site settings (site name) |
| `js/registry.js` | Topics, learning paths and packet colour categories |
| `js/modules/*.js` | One file per topic; each module is a data object |
| `js/app.js` | Routing, pages, diagram animation, playback |

## Content

| Topic | Modules |
| --- | --- |
| Internet Protocols | 16 |
| Web Application Security | 8 |
| API Security | 5 |
| Network Security | 5 |
| Cryptography | 4 |
| Defense & Blue Team | 4 |
| AI & LLM Security | 5 |

Identity & Access, Cloud, and Threats & Malware are defined but hidden until they have modules. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Responsible use

Everything here is for education. Only test systems you own or have written permission to test.
