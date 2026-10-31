# 🛡️ Securathon SOC Observability UI

This directory contains the standalone, decoupled frontend for the **Securathon Intelligent API Security Gateway**.

---

## 📂 Directory Structure

```
ui/
├── README.md               # Architecture and upgrade guide
├── package.json            # Scripts and configuration for local development / builds
├── public/                 # Static assets (Favicons, vector icons)
│   └── favicon.svg
└── src/                    # Modular source code
    ├── index.html          # Semantic HTML5 layout
    ├── css/
    │   └── dashboard.css   # Curated dark mode theme, CSS variables & animations
    └── js/
        ├── api.js          # Reusable Gateway WebSocket stream client
        ├── charts.js       # Chart.js donut chart controller
        └── app.js          # Event dispatcher, KPI counters, and DOM renderer
```

---

## 🚀 Running the UI

### 1. Integrated via Security Gateway (Recommended)
When the Gateway is running (`python3 -m gateway.main`), the dashboard is automatically served at:
- **`http://127.0.0.1:8000/dashboard`** (or `http://127.0.0.1:8000/`)

Static assets are routed under `/ui/*`.

### 2. Standalone Development Server
You can run the frontend independently using Python or Vite:
```bash
# Using Python built-in server (Port 3000):
npm run start
# OR:
python3 -m http.server 3000 -d src
```
Visit `http://localhost:3000`.

---

## 🔄 How to Upgrade the UI Later

This UI was built modularly to allow easy upgrades to modern frontend frameworks:

### Option A: Upgrading to React + Vite / Next.js
1. Initialize your preferred framework in this `ui/` directory:
   ```bash
   npm create vite@latest . -- --template react-ts
   # or
   npx create-next-app@latest .
   ```
2. Port the existing WebSocket handler from `src/js/api.js`:
   ```ts
   // Example React Hook:
   import { useEffect, useState } from 'react';
   
   export function useGatewayStream() {
     const [events, setEvents] = useState([]);
     useEffect(() => {
       const ws = new WebSocket("ws://127.0.0.1:8000/ws/security-stream");
       ws.onmessage = (e) => setEvents(prev => [JSON.parse(e.data), ...prev]);
       return () => ws.close();
     }, []);
     return events;
   }
   ```
3. Run `npm run build` to generate production assets into `ui/dist/`.
4. Point `DASHBOARD_FILE` in `gateway/main.py` to `ui/dist/index.html`.
