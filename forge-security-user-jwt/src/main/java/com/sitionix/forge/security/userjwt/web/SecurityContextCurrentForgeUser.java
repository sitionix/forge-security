package com.sitionix.forge.security.userjwt.web;

import com.sitionix.forge.security.userjwt.core.ForgeUser;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class SecurityContextCurrentForgeUser implements CurrentForgeUser {

    @Override
    public ForgeUser currentUser() {
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            return null;
        }
        final Object principal = authentication.getPrincipal();
        if (principal instanceof ForgeUser forgeUser) {
            return forgeUser;
        }
        final Object details = authentication.getDetails();
        if (details instanceof ForgeUser forgeUser) {
            return forgeUser;
        }
        return null;
    }
}
