package com.sitionix.forge.security.userjwt.client;

import java.security.interfaces.RSAPublicKey;
import java.util.Map;

public interface JwksClient {

    Map<String, RSAPublicKey> fetchKeys();
}
