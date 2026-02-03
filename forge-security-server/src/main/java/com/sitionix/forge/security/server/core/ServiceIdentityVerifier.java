package com.sitionix.forge.security.server.core;

import jakarta.servlet.http.HttpServletRequest;

public interface ServiceIdentityVerifier {

    ServiceIdentity verify(HttpServletRequest request);
}
