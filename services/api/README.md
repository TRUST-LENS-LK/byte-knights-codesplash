# TrustLens API

The local API runs on port 8787 by default.

```powershell
Copy-Item .env.example .env
npm.cmd start
```

Available endpoints:

- `GET /health`
- `POST /api/analyze`

The service-role key is server-only. Never expose it in the React app or commit `.env`.
