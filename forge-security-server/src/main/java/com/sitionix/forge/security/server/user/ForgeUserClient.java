package com.sitionix.forge.security.server.user;

/**
 * Provides access to the current end-user identity for internal service calls.
 */
public interface ForgeUserClient {

    /**
     * Returns the authenticated user id.
     *
     * @return current user id
     */
    Long getUserId();
}
