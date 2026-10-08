# Kupon Merkezi — Professional PWA + Consent-based Click Analytics

Static PWA frontend for GitHub Pages plus a separate Python analytics API. The frontend records a click only after explicit analytics consent. The backend stores an HMAC IP hash rather than the raw IP and requires a bearer token for reports.

## GitHub Pages
Publish the repository as a Pages site. The relative manifest/service-worker paths are intentional for project pages.

## Analytics
Set `ANALYTICS_BASE_URL` in the page deployment environment/build or replace it with the HTTPS URL of the analytics API. Configure the backend with `backend/.env` from the example.

## Report
`GET /api/report` requires `Authorization: Bearer <ADMIN_TOKEN>`.

## Production requirements
Use HTTPS, a reverse proxy with strict CORS, a long random `HASH_SECRET`, a long random `ADMIN_TOKEN`, rate limiting, backups, and an appropriate privacy notice/retention policy. Do not commit secrets.
