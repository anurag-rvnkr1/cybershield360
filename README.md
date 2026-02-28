# 🛡️ CyberShield 360 — 100% Free Tier

> Full-stack cybersecurity platform. **Zero cost. Zero compromises.**

[![Tests](https://github.com/yourusername/cybershield360-free/actions/workflows/deploy.yml/badge.svg)](https://github.com/yourusername/cybershield360-free/actions)
[![Free](https://img.shields.io/badge/Cost-$0%2Fmonth-brightgreen)](.)
[![Node](https://img.shields.io/badge/Node.js-20-green)](.)

---

## 💸 Premium vs Free — Feature Comparison

| Feature | Premium Version | This Free Version |
|---------|----------------|-------------------|
| Breach detection | HIBP paid API ($3.50/mo) | Open breach DB + HIBP free endpoint |
| Password pwned check | HIBP paid | **HIBP k-Anonymity (always free)** |
| Runtime | AWS ECS Fargate (~$15/mo) | **Railway.app free tier ($0)** |
| Cache | AWS ElastiCache ($12/mo) | **node-cache in-memory ($0)** |
| Container registry | AWS ECR ($0.10/mo) | **GitHub Container Registry ($0)** |
| Load balancer | AWS ALB ($18/mo) | **Railway reverse proxy ($0)** |
| SSL/HTTPS | ACM Certificate (free but ALB costs) | **Railway auto SSL ($0)** |
| CI/CD | GitHub Actions (paid over 2k min) | **GitHub Actions free tier ($0)** |
| Domain | Custom + Route53 (~$12/yr) | **yourapp.up.railway.app ($0)** |
| **TOTAL** | **~$47/month** | **$0/month** |

### What actually differs?
Only the breach email lookup uses our own open-source breach database instead of the HIBP paid API. The **password pwned check uses the exact same HIBP k-Anonymity endpoint** — it's always been free. Everything else is functionally identical.

---

## 🏗️ Architecture

```
Internet → Railway Reverse Proxy (auto HTTPS free)
              ↓
        Node.js Express (Railway free tier)
              ├── Serves frontend (Express static — no CDN needed)
              ├── /api/breach   → open breach DB + free HIBP range endpoint
              ├── /api/password → HIBP k-Anonymity + zxcvbn (free)
              ├── /api/phishing → local rules engine (free)
              └── node-cache    → in-memory (no Redis needed)
```

```
cybershield-free/
├── backend/
│   ├── src/
│   │   ├── server.js           # Express (serves API + frontend)
│   │   ├── routes/
│   │   │   ├── breach.js       # Open breach DB + HIBP free range API
│   │   │   ├── password.js     # k-Anonymity + zxcvbn + crypto
│   │   │   ├── phishing.js     # 9 URL + 13 email rules engine
│   │   │   ├── network.js      # Network info + scoring
│   │   │   └── health.js       # Railway health check
│   │   └── utils/
│   │       ├── cache.js        # node-cache (zero cost)
│   │       ├── logger.js       # console logger
│   │       └── validators.js
│   ├── public/
│   │   └── index.html          # Full CyberShield UI (served by Express)
│   ├── tests/api.test.js
│   ├── Dockerfile
│   ├── railway.json
│   └── package.json
├── .github/workflows/deploy.yml # Free CI/CD → GHCR → Railway
└── docker-compose.yml           # Local dev
```

---

## ⚡ Deploy in 5 Minutes (All Free)

### Step 1 — Fork & clone
```bash
# Fork this repo on GitHub (required for Railway GitHub integration)
git clone https://github.com/YOURNAME/cybershield360-free.git
cd cybershield360-free
```

### Step 2 — Deploy to Railway (free)
1. Go to **[railway.app](https://railway.app)** → Sign up with GitHub (free)
2. Click **New Project** → **Deploy from GitHub repo**
3. Select your forked repo → Select **backend/** as root directory
4. Railway auto-detects your Dockerfile and deploys it
5. Your app is live at `https://yourapp.up.railway.app` 🎉

That's it. **No config, no credit card, no environment variables needed.**

> Railway free tier: 500 hours/month (enough for 24/7 with one project), 512MB RAM, shared CPU, auto HTTPS, automatic redeploys on git push.

### Step 3 — Local development
```bash
# Option A: Docker (recommended)
docker compose up --build
# → http://localhost:3001

# Option B: Node directly
cd backend
cp .env.example .env
npm install
npm run dev
# → http://localhost:3001
```

### Step 4 — Run tests
```bash
cd backend
npm test
```

---

## 📡 API Reference

All endpoints work identically to the premium version.

### `POST /api/breach/email`
```bash
curl -X POST https://yourapp.up.railway.app/api/breach/email \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com"}'
```
```json
{
  "email": "test@example.com",
  "breached": true,
  "breachCount": 3,
  "riskScore": 67,
  "riskLevel": "HIGH",
  "breaches": [
    { "name": "LinkedIn", "domain": "linkedin.com", "breachDate": "2021-06-01",
      "pwnCount": 700000000, "dataClasses": ["Email addresses","Passwords","Names"] }
  ],
  "remediation": [
    { "priority": "CRITICAL", "action": "Change your password immediately..." }
  ]
}
```

### `POST /api/breach/check-password` — TRUE HIBP (always free)
```bash
curl -X POST https://yourapp.up.railway.app/api/breach/check-password \
  -H "Content-Type: application/json" \
  -d '{"password":"password123"}'
```
```json
{ "pwned": true, "pwnedCount": 7235615, "severity": "CRITICAL" }
```

### `GET /api/password/generate?length=32&symbols=true`
### `POST /api/password/analyze`  
### `POST /api/phishing/analyze-url`
### `POST /api/phishing/analyze-email`
### `GET /api/health`

---

## 🔐 How k-Anonymity Works (Why It's Free & Safe)

```
Your password: "mypassword123"
         ↓
SHA-1 hash: "2AA60A8FF7FCD473D321E0146AFD9E26E52F8048"
         ↓
Send only first 5 chars: "2AA60" → api.pwnedpasswords.com/range/2AA60
         ↓
HIBP returns ~500 hashes starting with "2AA60"
         ↓
We check locally if "A8FF7FCD473D321E0146AFD9E26E52F8048" is in the list
         ↓
Your full password NEVER left your server. HIBP never saw it.
This endpoint is FREE. No API key. 10 billion+ passwords indexed.
```

This is the same privacy model used by 1Password, Firefox Monitor, Google Password Checkup.

---

## 🏆 Interview Talking Points

1. **k-Anonymity privacy model** — how we check breached passwords without exposing them
2. **Railway free tier deployment** — auto HTTPS, Docker, zero-config
3. **GitHub Container Registry** — free Docker image hosting with GITHUB_TOKEN auth
4. **Single-container architecture** — Express serves both API and static frontend (no nginx needed)
5. **In-memory caching strategy** — node-cache TTLs prevent HIBP rate limiting
6. **Open-source breach intelligence** — 30 major breach sources, deterministic risk scoring
7. **Cost engineering** — identical feature set, $47/mo → $0/mo

---

## 🆙 Upgrade Path (When You Get Hired & Have Budget)

```
Free Tier → Production  (just change env vars)
────────────────────────────────────────────────
node-cache          → Upstash Redis (free 10k/day, then $0.20/100k)
Railway free        → Railway Pro ($5/mo) or AWS ECS ($47/mo)
Open breach DB      → HIBP paid API ($3.50/mo) for real-time data
GHCR                → AWS ECR ($0.10/mo)
yourapp.railway.app → Custom domain ($12/yr)
```
