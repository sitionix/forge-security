package com.sitionix.forge.security.server.core;

import java.time.Instant;
import java.util.List;

public record ServiceIdentity(String serviceId,
                              List<String> scopes,
                              Instant issuedAt,
                              Instant expiresAt,
                              String issuer,
                              String audience,
                              boolean policyBypass) {
}
