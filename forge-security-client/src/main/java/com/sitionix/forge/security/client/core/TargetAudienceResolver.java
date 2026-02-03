package com.sitionix.forge.security.client.core;

import org.springframework.http.HttpRequest;

public interface TargetAudienceResolver {

    String resolve(HttpRequest request);
}
