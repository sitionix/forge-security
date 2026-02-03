package com.sitionix.forge.security.server.web;

import com.sitionix.forge.security.server.core.ServiceIdentity;
import org.springframework.security.authentication.AbstractAuthenticationToken;

import java.util.Collections;

public class ServiceIdentityAuthenticationToken extends AbstractAuthenticationToken {

    private final ServiceIdentity identity;

    private ServiceIdentityAuthenticationToken(final ServiceIdentity identity) {
        super(Collections.emptyList());
        this.identity = identity;
        this.setAuthenticated(true);
    }

    public static ServiceIdentityAuthenticationToken authenticated(final ServiceIdentity identity) {
        return new ServiceIdentityAuthenticationToken(identity);
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public Object getPrincipal() {
        return this.identity;
    }

    public ServiceIdentity getIdentity() {
        return this.identity;
    }
}
