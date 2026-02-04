# Forge Security Server

Forge Security Server provides inbound service-to-service authentication and policy enforcement.

## Configuration

```yaml
forge:
  security:
    mode: dev-jwt # dev-jwt | mtls
    service-id: sitionix.auth
    accepted-audiences:
      - sitionix.auth
    services:
      auth:
        id: sitionix.auth
        hosts:
          - auth-service
          - authssox-service
          - localhost
      bff:
        id: sitionix.bff
        hosts:
          - bff-service
          - bffssox-service
    dev:
      jwt-secret: test-internal-secret
      issuer: sitionix-internal
      ttl-seconds: 300
    server:
      enabled: true
      excludes:
        - "/.well-known/jwks.json"
        - "/oauth2/v1/keys"
    policies:
      sitionix.bff:
        allow:
          - "*"
```

## Notes

- Unknown callers are denied by default.
- Missing/invalid identity returns 401; valid but not allowed returns 403.
- Do not log Authorization headers or JWTs.
- `aud` and `sub` must be logical service ids only.
- If `accepted-audiences` is empty, it defaults to the local `service-id`.
