package com.sitionix.forge.security.userjwt.core;

import java.util.Collections;
import java.util.List;

public class ForgeUser {

    private final String subject;
    private final String email;
    private final List<String> scopes;

    public ForgeUser(final String subject,
                     final String email,
                     final List<String> scopes) {
        this.subject = subject;
        this.email = email;
        this.scopes = scopes == null ? Collections.emptyList() : List.copyOf(scopes);
    }

    public String getSubject() {
        return this.subject;
    }

    public String getEmail() {
        return this.email;
    }

    public List<String> getScopes() {
        return this.scopes;
    }

    public boolean isAuthenticated() {
        return this.subject != null && !this.subject.isBlank();
    }
}
