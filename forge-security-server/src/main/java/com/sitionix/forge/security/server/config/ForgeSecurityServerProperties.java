package com.sitionix.forge.security.server.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@ConfigurationProperties(prefix = "forge.security")
public class ForgeSecurityServerProperties {

    private ForgeSecurityMode mode = ForgeSecurityMode.MTLS;

    private String serviceId;

    private DevJwt dev = new DevJwt();

    private final Server server = new Server();

    private Map<String, Policy> policies = new HashMap<>();

    private Map<String, ServiceDefinition> services = new HashMap<>();

    private List<String> acceptedAudiences = new ArrayList<>();

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

    public Server getServer() {
        return this.server;
    }

    public Map<String, Policy> getPolicies() {
        return this.policies;
    }

    public void setPolicies(final Map<String, Policy> policies) {
        this.policies = policies;
    }

    public Map<String, ServiceDefinition> getServices() {
        return this.services;
    }

    public void setServices(final Map<String, ServiceDefinition> services) {
        this.services = services;
    }

    public List<String> getAcceptedAudiences() {
        return this.acceptedAudiences;
    }

    public void setAcceptedAudiences(final List<String> acceptedAudiences) {
        this.acceptedAudiences = acceptedAudiences;
    }

    public static class Server {

        private boolean enabled = true;

        private List<String> excludes = new ArrayList<>(List.of("/.well-known/jwks.json", "/oauth2/v1/keys"));

        public boolean isEnabled() {
            return this.enabled;
        }

        public void setEnabled(final boolean enabled) {
            this.enabled = enabled;
        }

        public List<String> getExcludes() {
            return this.excludes;
        }

        public void setExcludes(final List<String> excludes) {
            this.excludes = excludes;
        }
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

    public static class Policy {

        private List<String> allow = new ArrayList<>();

        public List<String> getAllow() {
            return this.allow;
        }

        public void setAllow(final List<String> allow) {
            this.allow = allow;
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
