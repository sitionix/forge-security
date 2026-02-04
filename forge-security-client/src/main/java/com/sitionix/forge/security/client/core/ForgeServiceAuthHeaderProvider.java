package com.sitionix.forge.security.client.core;

import com.sitionix.forge.security.client.config.ForgeSecurityClientProperties;
import org.springframework.util.StringUtils;

public class ForgeServiceAuthHeaderProvider {

    private final ForgeSecurityClientProperties properties;
    private final ServiceJwtIssuer serviceJwtIssuer;

    public ForgeServiceAuthHeaderProvider(final ForgeSecurityClientProperties properties,
                                          final ServiceJwtIssuer serviceJwtIssuer) {
        this.properties = properties;
        this.serviceJwtIssuer = serviceJwtIssuer;
    }

    public String getAuthorizationValue(final String audience) {
        if (!StringUtils.hasText(audience)) {
            throw new IllegalArgumentException("Audience must be provided");
        }
        final String token = this.serviceJwtIssuer.issueToken(audience);
        return "Bearer " + token;
    }
}
