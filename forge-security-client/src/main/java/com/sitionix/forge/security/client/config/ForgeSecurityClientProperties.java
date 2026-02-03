package com.sitionix.forge.security.client.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "forge.security")
public class ForgeSecurityClientProperties {

    private ForgeSecurityMode mode = ForgeSecurityMode.MTLS;

    private String serviceName;

    private DevJwt dev = new DevJwt();

    private final Client client = new Client();

    public ForgeSecurityMode getMode() {
        return this.mode;
    }

    public void setMode(final ForgeSecurityMode mode) {
        this.mode = mode;
    }

    public String getServiceName() {
        return this.serviceName;
    }

    public void setServiceName(final String serviceName) {
        this.serviceName = serviceName;
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

    public Client getClient() {
        return this.client;
    }

    public static class DevJwt {

        private String jwtSecret;

        private String issuer = "sitionix-internal";

        private long ttlSeconds = 300;

        private String staticToken;

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

        public String getStaticToken() {
            return this.staticToken;
        }

        public void setStaticToken(final String staticToken) {
            this.staticToken = staticToken;
        }
    }

    public static class Client {

        private boolean enabled = true;

        public boolean isEnabled() {
            return this.enabled;
        }

        public void setEnabled(final boolean enabled) {
            this.enabled = enabled;
        }
    }
}
