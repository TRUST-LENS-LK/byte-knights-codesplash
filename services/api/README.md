# TrustLens API

The local API runs on port 8787 by default.

```powershell
Copy-Item .env.example .env
npm.cmd start
```

Available endpoints:

- `GET /health`
- `POST /api/analyze`
- `POST /api/reports`
- `POST /api/scanner/preview` validates URL safety without fetching the target.

The service-role key is server-only. Never expose it in the React app or commit `.env`.

The API accepts up to 60 analysis requests per client address in a 60-second window by default. Override `RATE_LIMIT_MAX` and `RATE_LIMIT_WINDOW_MS` in `.env` for local testing. Set `CORS_ORIGIN` to the exact frontend origin; do not use `*` when credentials or sensitive data are involved.
