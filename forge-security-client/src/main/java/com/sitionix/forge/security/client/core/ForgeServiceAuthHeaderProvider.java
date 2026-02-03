package com.sitionix.forge.security.client.core;

import com.sitionix.forge.security.client.config.ForgeSecurityClientProperties;
import com.sitionix.forge.security.client.config.ForgeSecurityMode;
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
        if (this.properties.getMode() != ForgeSecurityMode.DEV_JWT) {
            return null;
        }
        final String staticToken = this.properties.getDev().getStaticToken();
        if (StringUtils.hasText(staticToken)) {
            if (staticToken.regionMatches(true, 0, "Bearer ", 0, "Bearer ".length())) {
                return staticToken;
            }
            return "Bearer " + staticToken;
        }
        if (!StringUtils.hasText(audience)) {
            return null;
        }
        final String token = this.serviceJwtIssuer.issueToken(audience);
        return "Bearer " + token;
    }
}
