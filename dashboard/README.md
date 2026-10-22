# AXIOM RED — Frontend

A self-contained dashboard for the AXIOM RED agent. Light **and** dark theme, cross-browser,
offline-safe icons, HiDPI-crisp canvases. Wires to your existing FastAPI backend with no changes
to the backend's API contract.

```
frontend/
├── index.html   ← the dashboard page (icons, theme toggle, layout)
├── style.css    ← full design system + light/dark themes
├── app.js       ← all logic: scan start, WebSocket live feed, rendering, canvases
└── README.md    ← this file
```

---

## 1. Point it at your backend (the only config)

Open **`app.js`**, line 7:

```js
const API_BASE = "http://localhost:8000";
```

Set it to wherever your FastAPI backend runs. The WebSocket URL is **derived from this**
automatically (`http→ws`, `https→wss`), so this is the only line you ever change.

---

## 2. Serve the folder (recommended wiring)

The page uses **relative** asset paths (`style.css`, `app.js`), so serve `index.html` and its assets
from the same base. In your FastAPI `backend/main.py`, replace the dashboard-serving lines with a
single static mount **after** all your `@app.*` API routes:

```python
from fastapi.staticfiles import StaticFiles

# ... all your @app.get / @app.post / @app.websocket routes first ...

# then, LAST, mount the frontend at root:
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
```

- `html=True` serves `index.html` at `/` and `style.css` / `app.js` at `/style.css` / `/app.js`.
- It must be the **last** mount — a root catch-all shadows any route declared after it.
- Open **http://localhost:8000/** (not the file directly — the WebSocket needs the backend origin).

*Alternative:* if you keep your current `/static` mount, change the two refs in `index.html`
(`href="style.css"` → `href="/static/style.css"`, `src="app.js"` → `src="/static/app.js"`) instead.

---

## 3. Theme toggle

- Top-right **sun/moon** button switches light ⇄ dark. The choice is saved per browser
  (`localStorage`) and applied before first paint, so there's no flash on reload.
- First visit with no saved choice follows the OS setting (`prefers-color-scheme`); default is dark.
- Severity colours (Critical red, High orange, …) stay meaningful in **both** themes; the canvases
  (radar, attack graph) recolour automatically on toggle.

---

## 4. The backend contract (don't rename these)

`app.js` expects the standard AXIOM RED backend:

| What | Endpoint | Shape |
|---|---|---|
| Start scan | `POST {API_BASE}/api/scan/start` | body `{ target, llm_provider }` → `{ session_id }` |
| Live updates | `WS {API_BASE→ws}/ws/{session_id}` | messages `{type:"state_update"\|"done"\|"error", data}` |
| Report | `GET {API_BASE}/api/report/{session_id}` | HTML (shown in an iframe) |

The `data` payload is the agent's `AgentState` (findings, activity_log, risk_scores, attack_chains,
phase_complete, open_ports, web_endpoints, …). The element IDs in `index.html` are what `app.js`
reads/writes — if you add panels, keep the existing IDs intact.

**No backend? Try it instantly:** open the page and click **"Run Demo (no backend required)"** —
it plays a full engagement client-side so you can see every panel and both themes.

---

## 5. Cross-browser notes

- **Icons** are an inline SVG sprite (no icon CDN) → identical on Chrome, Edge, Firefox, Safari, and
  on a projector; works fully offline.
- **Fonts** load from Google Fonts with a system fallback stack, so a blocked/offline venue still
  renders cleanly (just without the custom faces).
- **Canvases** scale by `devicePixelRatio` → crisp on HiDPI laptops and projectors.
- `backdrop-filter` is `-webkit-`-prefixed; the stat-card accent uses `:has()` (supported in all
  current browsers; it degrades to a neutral border on anything older — no breakage).
- Responsive down to phone width; `prefers-reduced-motion` is respected.

---

*AXIOM RED · "Teach AI to Break It" @ Spectrona, NFSU.*
