# Send — minimal secure file transfer

A small self-hosted Send Anywhere-style file transfer web app with the same simple two-card interaction: **Send → +** and **Receive → key → download**.

## Features

- Public internet-ready HTTP service behind your HTTPS reverse proxy
- Multiple-file upload
- 6-digit transfer key
- 30-minute default expiry
- Automatic cleanup of expired transfers
- Maximum 20 download operations per transfer
- Download one file or all files as a ZIP
- Upload/download streaming to disk
- Helmet security headers
- API rate limiting
- File-name sanitization and path traversal protection
- Docker deployment
- No database required for a single-node deployment

## Run locally

```bash
npm install
npm start
```

Open `http://localhost:3000`.

## Run with Docker

```bash
docker compose up -d --build
```

Then open `http://YOUR_SERVER_IP:3000`.

## Put it on the internet securely

Expose the application through a reverse proxy such as Caddy or Nginx and use HTTPS. Do **not** expose port 3000 directly to the public internet without TLS and firewall controls.

Example Caddy configuration:

```caddyfile
send.example.com {
    reverse_proxy 127.0.0.1:3000
}
```

Point DNS for `send.example.com` to your server. Caddy will obtain and renew the TLS certificate.

## Configuration

Environment variables:

- `PORT` — application port, default `3000`
- `EXPIRY_MINUTES` — transfer lifetime, default `30`
- `MAX_FILES` — files per transfer, default `50`
- `MAX_FILE_SIZE` — max size per file in bytes, default `2147483648`
- `DATA_DIR` — storage path, default `./data`

## Security notes

The transfer key is a bearer credential. Anyone who has the key can retrieve the transfer until it expires or the download limit is reached. Use HTTPS in production.

This implementation is secure for a simple self-hosted file drop, but it is **not end-to-end encrypted**: the server receives and stores the uploaded files. For true E2E privacy, the browser can be upgraded to encrypt files with Web Crypto before upload and decrypt them only in the recipient browser.
