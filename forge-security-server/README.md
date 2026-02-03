# Forge Security Server

Forge Security Server provides inbound service-to-service authentication and policy enforcement.

## Configuration

```yaml
forge:
  security:
    mode: dev-jwt # dev-jwt | mtls
    service-name: authorisationservice-sox
    dev:
      jwt-secret: test-internal-secret
      issuer: sitionix-internal
      ttl-seconds: 300
      accepted-audiences:
        - authorisationservice-sox
    server:
      enabled: true
      excludes:
        - "/.well-known/jwks.json"
        - "/oauth2/v1/keys"
    policies:
      bffservice-sox:
        allow:
          - "*"
```

## IT kid bypass (optional)

Minimal IT config (single property):

```yaml
forge:
  security:
    dev: "<FULL_JWT_WITH_kid_it>"
```

Tokens with `kid` matching the static token are decoded without signature verification and can bypass policy checks
(only in the `it` profile; never in `prod`).

## Notes

- Unknown callers are denied by default.
- Missing/invalid identity returns 401; valid but not allowed returns 403.
- Do not log Authorization headers or JWTs.
