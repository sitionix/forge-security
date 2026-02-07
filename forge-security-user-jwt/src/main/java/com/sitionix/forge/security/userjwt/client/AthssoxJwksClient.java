package com.sitionix.forge.security.userjwt.client;

import com.app_afesox.athssox.client.api.SecurityApi;
import com.app_afesox.athssox.client.dto.JwksResponseDTO;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClientException;

import java.security.interfaces.RSAPublicKey;
import java.util.Map;

public class AthssoxJwksClient implements JwksClient {

    private final SecurityApi securityApi;
    private final JwkRsaKeyConverter keyConverter;
    private final JwksEndpoint endpoint;

    public AthssoxJwksClient(final SecurityApi securityApi,
                             final JwkRsaKeyConverter keyConverter,
                             final JwksEndpoint endpoint) {
        this.securityApi = securityApi;
        this.keyConverter = keyConverter;
        this.endpoint = endpoint;
    }

    @Override
    public Map<String, RSAPublicKey> fetchKeys() {
        final JwksResponseDTO response = this.fetchResponse();
        return this.keyConverter.toPublicKeys(response);
    }

    private JwksResponseDTO fetchResponse() {
        try {
            final ResponseEntity<JwksResponseDTO> response = this.endpoint == JwksEndpoint.ALIAS
                    ? this.securityApi.getJwksAliasWithHttpInfo()
                    : this.securityApi.getJwksCanonicalWithHttpInfo();
            return response.getBody();
        } catch (final RestClientException ex) {
            throw new JwksClientException("Failed to fetch JWKS", ex);
        }
    }
}
