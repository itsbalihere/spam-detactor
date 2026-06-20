# Deployment Notes

This version uses SQLite, so it does not need `MYSQL_HOST`, `MYSQL_USER`, or any external MySQL server.

## Docker

Build and run:

```bash
docker build -t spam-detector .
docker run -p 8000:8000 -v spam_detector_data:/data spam-detector
```

The Dockerfile stores the SQLite database at:

```env
SPAM_DETECTOR_DB=/data/spam_detector.sqlite3
```

Keep `/data` as a persistent volume if your hosting provider supports volumes. Without a persistent disk, accounts and API keys can reset after redeploy.

## Docker Compose

```bash
docker compose up --build
```

The included `docker-compose.yml` creates a persistent `sqlite_data` volume automatically.
