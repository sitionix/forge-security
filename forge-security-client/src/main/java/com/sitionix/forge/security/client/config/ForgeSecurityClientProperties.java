package com.sitionix.forge.security.client.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.HashMap;
import java.util.Map;

@ConfigurationProperties(prefix = "forge.security")
public class ForgeSecurityClientProperties {

    private String serviceId;

    private DevJwt dev = new DevJwt();

    private Map<String, TargetDefinition> targets = new HashMap<>();

    public String getServiceId() {
        return this.serviceId;
    }

    public void setServiceId(final String serviceId) {
        this.serviceId = serviceId;
    }

    public DevJwt getDev() {
        return this.dev;
    }

    public void setDev(final DevJwt dev) {
        if (dev == null) {
            return;
        }
        this.dev = dev;
    }

    public Map<String, TargetDefinition> getTargets() {
        return this.targets;
    }

    public void setTargets(final Map<String, TargetDefinition> targets) {
        this.targets = targets;
    }

    public static class DevJwt {

        private String jwtSecret;

        private String issuer = "sitionix-internal";

        private long ttlSeconds = 300;

        public String getJwtSecret() {
            return this.jwtSecret;
        }

        public void setJwtSecret(final String jwtSecret) {
            this.jwtSecret = jwtSecret;
        }

        public String getIssuer() {
            return this.issuer;
        }

        public void setIssuer(final String issuer) {
            this.issuer = issuer;
        }

        public long getTtlSeconds() {
            return this.ttlSeconds;
        }

        public void setTtlSeconds(final long ttlSeconds) {
            this.ttlSeconds = ttlSeconds;
        }
    }

    public static class TargetDefinition {

        private String host;

        public String getHost() {
            return this.host;
        }

        public void setHost(final String host) {
            this.host = host;
        }
    }
}
