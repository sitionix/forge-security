# Forge Security Server

Forge Security Server provides inbound service-to-service authentication and policy enforcement.

## Configuration

```yaml
forge:
  security:
    service-id: sitionixAuth
    dev:
      jwt-secret: test-internal-secret
      issuer: sitionix-internal
      ttl-seconds: 300
    server:
      excludes:
        - "/.well-known/jwks.json"
        - "/oauth2/v1/keys"
    policies:
      sitionixBff:
        allow:
          - "*"
      sitionixNotification:
        allow:
          - "GET /api/v1/auth/emailVerificationTokens/*:issueLink"
```

## Notes

- Unknown callers are denied by default.
- Missing/invalid identity returns 401; valid but not allowed returns 403.
- Do not log Authorization headers or JWTs.
- `sub` is the logical caller id.
- `aud` must equal the local `service-id`.
