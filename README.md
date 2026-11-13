# QazGuard Business — Render cloud edition

Cloud copy of the local educational pilot. Synthetic records only. The local
SQLite database, account hashes, screenshots, logs and API keys are not included.

## Render

Free Web Service; build `pip install -r requirements.txt`; start:

`gunicorn cloud:app --bind 0.0.0.0:$PORT --workers 1 --threads 8 --timeout 180 --access-logfile /dev/null`

One worker is required for in-memory sessions, per-user rate limiting and the
provider queue. Sessions expire after eight hours and are reset on restart.
Free Render sleeps during inactivity. Use persistent external PostgreSQL (Neon).
Never substitute ephemeral SQLite in a public deployment.

Environment variables (configure only in Render settings):

- `DATABASE_URL`: Neon PostgreSQL URL with TLS (`sslmode=require`).
- `SETUP_CODE`: long random owner-only initial setup code. Required only while
  no users exist; prevents a public visitor from claiming the administrator.
- `GEMINI_API_KEY`, `GEMINI_MODEL`: server-side Gemini credentials/model.
- `QAZGUARD_PROVIDER`: `gemini` or `offline`.
- `PUBLIC_ORIGIN`: HTTPS site origin, optional on Render where
  `RENDER_EXTERNAL_URL` supplies it automatically. No trailing slash.

The first administrator enters the setup code and chooses their own password.
Public visitors see the login page; business records require login. There is no
public self-registration after the first administrator exists. Render account
access and repository access must stay limited to the owner.

The seed creates 12 synthetic clients, 24 orders and 16 payments once. Existing
local records are not automatically migrated. The backup link exports business
records as JSON, excluding authentication data; automatic restore is not built.
Ollama runs on a laptop and is not available from Render's localhost.

SQL reports are computed by code; AI prose can be wrong. Names and companies in
selected database context are tokenized, while free-text names/addresses may not
be detected. This remains an educational pilot, not an audited DLP product.

## Checks

`python -m unittest test_cloud`

Tests use an isolated SQLite fixture only with `QAZGUARD_TESTING=1` and never
call Gemini. Schema creation, inserts, payment/overpayment checks and report sums passed on an isolated Neon validation branch. Render-to-Neon integration still needs a live deployment check.

Neon CLI setup is complete: `.env.local` is loaded privately by `cloud.py` and
excluded from Git. Read-only CLI inspection succeeded; eight isolated tests
passed. Source upload is complete; publishing and initial owner setup are still pending. Configure both
DATABASE_URL and DATABASE_URL_UNPOOLED privately in Render.
