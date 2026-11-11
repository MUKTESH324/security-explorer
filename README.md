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

## Pages and SEO

`scripts/build_pages.py` runs in the deploy workflow and writes a real page for every route (`/m/<id>/`, `/modules/<topic>/`, `/paths/`, `/about/`) with its own title, description and canonical link, plus `404.html`, `sitemap.xml` and `robots.txt`. These files are generated during deploy, not committed. To preview them locally, run it on a copy of the folder.

## Contact form

The Contact page posts to `/api/contact`, served by the Cloudflare Worker in `workers/contact/`. It checks the request (same-origin, size, honeypot field, minimum time on page) and emails the message through Cloudflare Email Routing. The destination inbox is a Worker secret, never stored in this repository.

```bash
cd workers/contact
npx wrangler deploy
npx wrangler secret put DESTINATION   # verified Email Routing destination address
```

## Project layout

| Path | What it is |
| --- | --- |
| `index.html` | Page shell: header, explorer, footer, search |
| `css/style.css` | All styles; light and dark themes via CSS variables |
| `js/config.js` | Site settings (site name) |
| `js/registry.js` | Topics, learning paths and packet colour categories |
| `js/modules/*.js` | One file per topic; each module is a data object |
| `js/quizzes.js` | End-of-module quiz questions, keyed by module id |
| `js/glossary.js` | Glossary terms, with links to related modules |
| `js/app.js` | Routing, pages, diagram animation, playback |
| `scripts/build_pages.py` | Pre-builds one page per route, structured data and sitemap at deploy time |
| `og-image.svg` / `og-image.png` | Link preview image (edit the SVG, re-export the PNG at 1200×630) |
| `workers/contact/` | Cloudflare Worker behind the contact form (`/api/contact`), delivers messages via Email Routing |
| `.well-known/security.txt` | How to report a security issue with the site (renew `Expires` yearly) |

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
