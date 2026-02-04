# Forge Security Client

Forge Security Client auto-attaches service JWTs to outbound HTTP calls in dev-jwt mode.

## Configuration

```yaml
forge:
  security:
    mode: dev-jwt # dev-jwt | mtls
    service-id: sitionix.bff
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
    client:
      enabled: true
```

## Notes

- Uses RestTemplate interceptors; no per-call wiring required.
- In mtls mode, the interceptor is a no-op.
- Do not log Authorization headers or JWTs.
- Hostnames are mapped to logical service ids via `forge.security.services`.
- `sub` and `aud` are always logical service ids.
- Override `TargetAudienceResolver` with a custom bean if you need non-host resolution.
