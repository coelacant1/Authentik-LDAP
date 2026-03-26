# Authentik-LDAP

Configuration and policy code for an [Authentik](https://goauthentik.io/) instance integrated with Active Directory via LDAP. This setup provides self-service account enrollment, password recovery, and account management for LDAP-synced users restricted to a configurable email domain.

## Architecture

Internet traffic routes through a **Cloudflare Tunnel** for DNS and TLS, then to **Nginx Proxy Manager** which reverse-proxies subdomains to Authentik and downstream applications. Nginx integrates with the Authentik outpost for forward-auth protection on apps.

**Authentik** handles authentication, enrollment, and recovery flows. A custom **AD User API** (Flask) runs alongside Authentik and manages AD account creation, status checks, and account enabling/unlocking over LDAPS. An **LDAP Source** syncs users and groups from Active Directory with password writeback enabled.

All flows are defined as portable [Authentik blueprints](https://docs.goauthentik.io/docs/customize/blueprints/) using `!Find` and `!KeyOf` references instead of hardcoded UUIDs.

## User Lifecycle

- **Enrollment** - User registers with an allowed email domain -> CAPTCHA -> AD account created via API -> user directed to log in and set password via recovery.
- **Authentication** - Username/email identification -> password (LDAP backend) -> account status check (blocks disabled/locked accounts) -> MFA -> session.
- **Password Recovery** - Email identification -> verification email -> new password -> AD account re-enabled if disabled -> redirect to login.
- **Logout** - Session invalidation.

## Flows

| Flow | Blueprint | Purpose |
|------|-----------|---------|
| Authentication | `default-authentication-flow.yaml` | Login with LDAP password, account status check, MFA |
| Enrollment | `default-enrollment-flow.yaml` | Self-service registration (email domain restricted) |
| Recovery | `default-recovery-flow.yaml` | Password reset with AD account re-enable |
| Invalidation | `default-invalidation-flow.yaml` | Logout / session destroy |
| Source Auth | `default-source-authentication.yaml` | Post-SSO IdP login |
| Source Enrollment | `default-source-enrollment.yaml` | SSO user onboarding |

## Expression Policies

| Policy | Purpose |
|--------|---------|
| `block-disabled-accounts` | Checks AD account status via API; blocks disabled/locked users at login |
| `create-ad-user` | Calls the AD User API to create a new account during enrollment |
| `email-domain-restriction` | Restricts enrollment to configured email domains |
| `enable-ldap-account-on-verification` | Re-enables AD account and resets password during recovery |

## AD User API

A Flask REST API that bridges Authentik with Active Directory for account management. Runs as a systemd service on the Authentik host.

See [api/README.md](api/README.md) for endpoints, deployment, and configuration.

## Deployment

Authentik is deployed via [Docker Compose](https://goauthentik.io/docs/install-config/install/docker-compose) using the standard `compose.yml`. See `authentik/.env.example` for the required environment variables including SMTP configuration.

All placeholder values (e.g. `<YOUR_DOMAIN>`, `<API_KEY>`, `<AD_SERVER_IP>`) must be replaced with your own values before use. See `.private/README.md` for a full placeholder reference if using the private configuration overlay.

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
