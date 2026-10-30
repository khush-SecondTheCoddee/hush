# hush

Hush is an anonymous chat prototype for Android browsers and localhost. It includes encrypted private notes, anonymous server accounts, changeable usernames, QR invitations, and direct WebRTC chats. It does not ask for names, email addresses, phone numbers, contacts, or other personal details.

## Run locally

Use Node.js 22.5 or newer:

```sh
npm start
```

Open http://localhost:4173 and create a vault passphrase. The server binds to `127.0.0.1` by default and stores its SQLite database in `data/chat.sqlite`. Run `npm run check` for JavaScript syntax checks.

## Identity and data

The server creates a random immutable PUID for each account and uses it internally. It does not return the PUID through the app API. Usernames are public, searchable on the instance, and changeable; changing a username does not change the PUID. With no identity verification or personal information, the server can guarantee uniqueness per account, not per human.

Private-note content is encrypted in the browser with AES-256-GCM before it is stored. The key is derived from the vault passphrase using PBKDF2 and is not sent to the server. Peer chat uses WebRTC, ECDH key agreement, and AES-GCM inside the data channel; users must compare a safety code over a separate trusted channel. The server sees usernames, signaling offers/answers (including network candidates), timing, and ciphertext metadata. There is no STUN/TURN relay, offline delivery, multi-device history sync, account recovery, moderation, or abuse-report flow. Direct connections may fail outside a shared local network.

The SQLite database, its WAL/shared-memory files, and `.env` files are ignored by Git. Set `HUSH_DATA_DIR` to choose the runtime database directory. The process applies restrictive file permissions when creating it.

## Render deployment

Connect a Git repository to a Render Web Service. Use build command `npm install` and start command `npm start`. Set `HOST=0.0.0.0`, `TRUST_PROXY=1`, and `HUSH_DATA_DIR=/var/data`; set health check path `/api/v1/health`. Render supplies `PORT`. For a paid single-instance service, mount a persistent disk at `/var/data` so the PUID/account database survives deploys and restarts.

Render Free services sleep after inactivity and have ephemeral local filesystems. This app's SQLite accounts and PUIDs can be lost on sleep or restart, so Free is only suitable for a disposable demo. The app uses a single-process SQLite store and is not horizontally scalable. See [Render free plan limits](https://render.com/docs/free), [web service requirements](https://render.com/docs/web-services), and [persistent disks](https://render.com/docs/disks).

## Production readiness

**This project is not ready for production users.** The current E2EE and P2P protocol has not had an independent cryptographic review; there is no TURN relay, reliable multi-device or offline delivery, account recovery, abuse/moderation operation, database backup/restore procedure, or production incident monitoring. A database migration to a managed relational service is needed before horizontal scaling.

**Git history cleanup:** An earlier commit tracked SQLite database/WAL files containing account PUIDs and session records. This release replaces that branch history and removes those files from the published tree; old clones, forks, cached commits, or other remotes may still retain the prior data. Treat those records as exposed and rotate/revoke affected sessions where applicable. Existing PUIDs are immutable by design, so repository cleanup cannot rotate them. Never put runtime database or WAL files in source control.

Before real deployment, complete the cryptographic review, persistence/backup design, TURN deployment, and abuse-response plan.
