package com.sitionix.forge.security.userjwt.web;

import com.sitionix.forge.security.userjwt.core.ForgeUser;
import org.springframework.security.authentication.AbstractAuthenticationToken;

import java.util.Collections;

public class UserJwtAuthenticationToken extends AbstractAuthenticationToken {

    private final ForgeUser principal;

    private UserJwtAuthenticationToken(final ForgeUser principal) {
        super(Collections.emptyList());
        this.principal = principal;
        this.setAuthenticated(true);
    }

    public static UserJwtAuthenticationToken authenticated(final ForgeUser principal) {
        return new UserJwtAuthenticationToken(principal);
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    public ForgeUser getUserPrincipal() {
        return this.principal;
    }

    @Override
    public String getName() {
        return this.principal != null ? this.principal.getSubject() : "";
    }
}
