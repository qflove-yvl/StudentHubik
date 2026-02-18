# Operations checklist (reliability-first)

## 1) Migrations
Use Flask-Migrate instead of ad-hoc schema edits for controlled rollout.

```bash
flask db init
flask db migrate -m "init"
flask db upgrade
```

## 2) Health endpoints
- `GET /health` – liveness
- `GET /ready` – database readiness

## 3) Error monitoring
Set `SENTRY_DSN` to send production exceptions to Sentry.

## 4) CI gate
GitHub Actions runs compile checks and tests on each push/PR.

## 5) Strong production secrets
In production, app raises an error if `SECRET_KEY` is weak and
`REQUIRE_STRONG_SECRET_IN_PROD=1`.
