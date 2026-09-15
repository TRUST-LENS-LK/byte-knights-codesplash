# TrustLens LK

## Local development

Install dependencies from the repository root:

```powershell
npm.cmd install
```

Run the API and frontend in separate terminals:

```powershell
npm.cmd run start:api
npm.cmd run dev:web
```

The API is available at `http://localhost:8787`; the Vite frontend normally runs at `http://localhost:5173`.

Run the backend checks before opening a pull request:

```powershell
npm.cmd run check:api
npm.cmd run test:api
npm.cmd run build:web
npm.cmd run lint:web
```

The API keeps submitted content out of Supabase unless `retentionConsent` is explicitly `true`. Keep `services/api/.env` local and never commit its contents.
