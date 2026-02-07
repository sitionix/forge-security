package com.sitionix.forge.security.userjwt.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "forge.user-jwt")
public class ForgeUserJwtProperties {

    private String authBaseUrl;

    private String jwksPath = "/.well-known/jwks.json";

    private long cacheTtlSeconds = 300;

    private int connectTimeoutMs = 1000;

    private int readTimeoutMs = 2000;

    private String issuer;

    private String audience;

    private long clockSkewSeconds = 30;

    public String getAuthBaseUrl() {
        return this.authBaseUrl;
    }

    public void setAuthBaseUrl(final String authBaseUrl) {
        this.authBaseUrl = authBaseUrl;
    }

    public String getJwksPath() {
        return this.jwksPath;
    }

    public void setJwksPath(final String jwksPath) {
        this.jwksPath = jwksPath;
    }

    public long getCacheTtlSeconds() {
        return this.cacheTtlSeconds;
    }

    public void setCacheTtlSeconds(final long cacheTtlSeconds) {
        this.cacheTtlSeconds = cacheTtlSeconds;
    }

    public int getConnectTimeoutMs() {
        return this.connectTimeoutMs;
    }

    public void setConnectTimeoutMs(final int connectTimeoutMs) {
        this.connectTimeoutMs = connectTimeoutMs;
    }

    public int getReadTimeoutMs() {
        return this.readTimeoutMs;
    }

    public void setReadTimeoutMs(final int readTimeoutMs) {
        this.readTimeoutMs = readTimeoutMs;
    }

    public String getIssuer() {
        return this.issuer;
    }

    public void setIssuer(final String issuer) {
        this.issuer = issuer;
    }

    public String getAudience() {
        return this.audience;
    }

    public void setAudience(final String audience) {
        this.audience = audience;
    }

    public long getClockSkewSeconds() {
        return this.clockSkewSeconds;
    }

    public void setClockSkewSeconds(final long clockSkewSeconds) {
        this.clockSkewSeconds = clockSkewSeconds;
    }
}
