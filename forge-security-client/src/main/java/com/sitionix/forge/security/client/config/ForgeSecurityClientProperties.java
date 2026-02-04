package com.sitionix.forge.security.client.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@ConfigurationProperties(prefix = "forge.security")
public class ForgeSecurityClientProperties {

    private ForgeSecurityMode mode = ForgeSecurityMode.MTLS;

    private String serviceId;

    private DevJwt dev = new DevJwt();

    private final Client client = new Client();

    private Map<String, ServiceDefinition> services = new HashMap<>();

    public ForgeSecurityMode getMode() {
        return this.mode;
    }

    public void setMode(final ForgeSecurityMode mode) {
        this.mode = mode;
    }

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

    public Client getClient() {
        return this.client;
    }

    public Map<String, ServiceDefinition> getServices() {
        return this.services;
    }

    public void setServices(final Map<String, ServiceDefinition> services) {
        this.services = services;
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

    public static class ServiceDefinition {

        private String id;

        private List<String> hosts = new ArrayList<>();

        public String getId() {
            return this.id;
        }

        public void setId(final String id) {
            this.id = id;
        }

        public List<String> getHosts() {
            return this.hosts;
        }

        public void setHosts(final List<String> hosts) {
            this.hosts = hosts;
        }
    }
}
