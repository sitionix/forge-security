package com.sitionix.forge.security.server.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@ConfigurationProperties(prefix = "forge.security")
public class ForgeSecurityServerProperties {

    private ForgeSecurityMode mode = ForgeSecurityMode.MTLS;

    private String serviceName;

    private DevJwt dev = new DevJwt();

    private final Server server = new Server();

    private Map<String, Policy> policies = new HashMap<>();

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

    public Server getServer() {
        return this.server;
    }

    public Map<String, Policy> getPolicies() {
        return this.policies;
    }

    public void setPolicies(final Map<String, Policy> policies) {
        this.policies = policies;
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

        private List<String> acceptedAudiences = new ArrayList<>();

        private long ttlSeconds = 300;

        private String staticToken;

        private boolean itKidBypassEnabled = false;

        private String itKid = "it";

        private boolean itIgnoreExpiry = true;

        private boolean itBypassPolicies = true;

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

        public List<String> getAcceptedAudiences() {
            return this.acceptedAudiences;
        }

        public void setAcceptedAudiences(final List<String> acceptedAudiences) {
            this.acceptedAudiences = acceptedAudiences;
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

        public boolean isItKidBypassEnabled() {
            return this.itKidBypassEnabled;
        }

        public void setItKidBypassEnabled(final boolean itKidBypassEnabled) {
            this.itKidBypassEnabled = itKidBypassEnabled;
        }

        public String getItKid() {
            return this.itKid;
        }

        public void setItKid(final String itKid) {
            this.itKid = itKid;
        }

        public boolean isItIgnoreExpiry() {
            return this.itIgnoreExpiry;
        }

        public void setItIgnoreExpiry(final boolean itIgnoreExpiry) {
            this.itIgnoreExpiry = itIgnoreExpiry;
        }

        public boolean isItBypassPolicies() {
            return this.itBypassPolicies;
        }

        public void setItBypassPolicies(final boolean itBypassPolicies) {
            this.itBypassPolicies = itBypassPolicies;
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
}
