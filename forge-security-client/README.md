# Forge Security Client

Forge Security Client auto-attaches service JWTs to outbound HTTP calls in dev-jwt mode.

## Configuration

```yaml
forge:
  security:
    mode: dev-jwt # dev-jwt | mtls
    service-name: bffservice-sox
    dev:
      jwt-secret: test-internal-secret
      issuer: sitionix-internal
      ttl-seconds: 300
      static-token: "<FULL_JWT_WITH_kid_it>"
    client:
      enabled: true
```

## Notes

- Uses RestTemplate interceptors; no per-call wiring required.
- In mtls mode, the interceptor is a no-op.
- Do not log Authorization headers or JWTs.
- Override `TargetAudienceResolver` with a custom bean if host-based audiences are not enough.

Minimal IT config (single property):
```yaml
forge:
  security:
    dev: "<FULL_JWT_WITH_kid_it>"
```
