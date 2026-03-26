# AD User API

A Flask REST API that manages Active Directory user accounts on behalf of Authentik. It handles account creation during enrollment, status checks during login, and account re-enabling during password recovery.

## Endpoints

### `GET /health`

Health check. No authentication required.

```
curl http://localhost:5000/health
```
```json
{"status": "ok"}
```

---

### `POST /create-user`

Creates a new AD user account in the Students OU and adds them to the Students security group. Generates a secure random password (the user sets their real password via Authentik's recovery flow).

**Headers:** `Authorization: Bearer <API_KEY>`

**Request body:**

```json
{
  "email": "jsmith@example.edu",
  "name": "John Smith"
}
```

Also accepts Authentik webhook format where email/name are nested under `body.context.prompt_data`.

**Responses:**

| Code | Meaning |
|------|---------|
| 200 | Account created successfully |
| 400 | Missing required fields |
| 403 | Email domain not in allowlist |
| 409 | User already exists |
| 500 | AD bind failure or creation error |

**Success response:**

```json
{
  "success": true,
  "username": "jsmith",
  "message": "Account created for John Smith",
  "group_status": "User added to Students group"
}
```

**What it does in AD:**
1. Validates email domain (`@<EMAIL_DOMAIN>`)
2. Derives username from email prefix (`jsmith@example.edu` -> `jsmith`)
3. Checks if `sAMAccountName` already exists
4. Creates user object in `<STUDENTS_OU>`
5. Sets: `cn`, `givenName`, `sn`, `displayName`, `sAMAccountName`, `userPrincipalName`, `mail`, `unicodePwd`
6. Sets `userAccountControl=512` (enabled, normal account)
7. Adds user to the `Students` security group

---

### `POST /check-user-status`

Checks whether an AD account is enabled, disabled, or locked. Used by the `block-disabled-accounts` policy during login.

**Headers:** `Authorization: Bearer <API_KEY>`

**Request body:**

```json
{
  "email": "jsmith@example.edu"
}
```

**Responses:**

| Code | Meaning |
|------|---------|
| 200 | Status retrieved |
| 400 | Missing email |
| 404 | User not found in AD |
| 500 | AD connection error |

**Success response:**

```json
{
  "success": true,
  "is_active": true,
  "is_locked": false,
  "userAccountControl": 512,
  "lockoutTime": 0
}
```

**Status logic:**
- `is_active = false` when UAC bit 2 (`ACCOUNTDISABLE`) is set
- `is_locked = true` when `lockoutTime > 0`

---

### `POST /enable-user`

Re-enables a disabled account and/or unlocks a locked account. Used by the `enable-ldap-account-on-verification` policy during password recovery.

**Headers:** `Authorization: Bearer <API_KEY>`

**Request body:**

```json
{
  "email": "jsmith@example.edu"
}
```

Also accepts Authentik webhook format (checks `body.context.prompt_data.email` and `body.user.email`).

**Responses:**

| Code | Meaning |
|------|---------|
| 200 | Account enabled/unlocked (or already was) |
| 400 | Missing email |
| 404 | User not found in AD |
| 500 | AD bind or modification error |

**Success response:**

```json
{
  "success": true,
  "message": "Account jsmith: enabled account (UAC: 514 -> 512), unlocked account",
  "username": "jsmith",
  "actions": ["enabled account (UAC: 514 -> 512)", "unlocked account"]
}
```

**What it does:**
- Clears UAC bit 2 (`ACCOUNTDISABLE`) and ensures bit 9 (`NORMAL_ACCOUNT`) is set
- Resets `lockoutTime` to `0` if account is locked

## Deployment

### Prerequisites

- Python 3.10+
- Network access to the AD domain controller over LDAPS (port 636)
- A service account in AD with permissions to create/modify user objects

### Install

```bash
# Create working directory
sudo mkdir -p /opt/ad-user-api
cd /opt/ad-user-api

# Copy the API script
cp ad_user_api.py /opt/ad-user-api/

# Create virtual environment and install dependencies
sudo python3 -m venv /opt/ad-user-api/venv
sudo /opt/ad-user-api/venv/bin/pip install flask ldap3
```

### Configure as systemd Service

```bash
# Copy the service file
sudo cp ad-user-api.service /etc/systemd/system/

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable ad-user-api
sudo systemctl start ad-user-api

# Verify
sudo systemctl status ad-user-api
curl http://localhost:5000/health
```

### Configuration

The following values are configured at the top of `ad_user_api.py`:

| Variable | Description |
|----------|-------------|
| `API_KEY` | Bearer token for authenticating requests |
| `AD_SERVER` | LDAPS URL for the domain controller |
| `AD_BIND_USER` | Distinguished name of the service account |
| `AD_BIND_PASSWORD` | Service account password |
| `STUDENTS_OU` | DN of the OU where new users are created |
| `USERS_SEARCH_BASE` | DN used for user search queries |
| `STUDENTS_GROUP_DN` | DN of the security group new users are added to |
| `ALLOWED_DOMAINS` | List of permitted email domains |

### Logs

```bash
# View service logs
journalctl -xeu ad-user-api.service

# Follow logs in real-time
journalctl -fu ad-user-api.service
```

## How Authentik Uses This API

| Authentik Component | API Endpoint | Trigger |
|---------------------|-------------|---------|
| `create-ad-user` policy | `/create-user` | User completes enrollment flow |
| `block-disabled-accounts` policy | `/check-user-status` | User attempts login |
| `enable-ldap-account-on-verification` policy | `/enable-user` | User completes email verification in recovery flow |
| `ad-user-Creation` webhook | `/create-user` | User creation event (backup trigger) |

All policies authenticate using `Authorization: Bearer <API_KEY>` and communicate over HTTP on `localhost:5000` / `<AUTHENTIK_IP>:5000`.
