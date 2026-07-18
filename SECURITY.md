# Security Policy

## Secrets

Do not commit API keys, tokens, credentials, exported browser sessions, or `.env` files.

Live enrichment keys must be provided through environment variables:

- `ABUSEIPDB_API_KEY`
- `VT_API_KEY`

The committed `.env.example` file is only a template and must not contain real values.

## Important Note for Maintainers

If a real key was ever stored in local source code or shared outside the machine, rotate it in the provider dashboard before publishing or using the repository in another environment.

## Responsible Use

This project processes threat-intelligence and security-log text. Avoid committing real client logs, sensitive infrastructure details, private IP inventories, hostnames, usernames, case IDs, or unredacted evidence exports.
