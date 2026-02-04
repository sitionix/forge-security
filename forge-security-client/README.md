# Forge Security Client

Forge Security Client auto-attaches service JWTs to outbound HTTP calls.

## Configuration

```yaml
forge:
  security:
    service-id: sitionixBff
    dev:
      jwt-secret: test-internal-secret
      issuer: sitionix-internal
      ttl-seconds: 300
    targets:
      sitionixAuth:
        host: auth-service
```

## Notes

- Uses RestTemplate interceptors; no per-call wiring required.
- Do not log Authorization headers or JWTs.
- Hostnames are mapped to logical service ids via `forge.security.targets.<id>.host` (one host per target).
- `sub` is the local `service-id`, `aud` is the resolved target id.
- Override `TargetAudienceResolver` with a custom bean if you need non-host resolution.
