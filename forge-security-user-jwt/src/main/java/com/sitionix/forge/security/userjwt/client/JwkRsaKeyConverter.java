package com.sitionix.forge.security.userjwt.client;

import com.app_afesox.athssox.client.dto.JwkDTO;
import com.app_afesox.athssox.client.dto.JwksResponseDTO;
import org.springframework.util.StringUtils;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class JwkRsaKeyConverter {

    public Map<String, RSAPublicKey> toPublicKeys(final JwksResponseDTO response) {
        final List<JwkDTO> keys = response == null ? null : response.getKeys();
        if (keys == null || keys.isEmpty()) {
            throw new JwksClientException("JWKS response did not contain keys");
        }
        final Map<String, RSAPublicKey> result = new HashMap<>();
        for (final JwkDTO jwk : keys) {
            if (jwk == null) {
                continue;
            }
            if (!"RSA".equalsIgnoreCase(jwk.getKty())) {
                continue;
            }
            if (!StringUtils.hasText(jwk.getKid())
                    || !StringUtils.hasText(jwk.getN())
                    || !StringUtils.hasText(jwk.getE())) {
                continue;
            }
            final RSAPublicKey publicKey = this.toPublicKey(jwk.getN(), jwk.getE());
            result.put(jwk.getKid(), publicKey);
        }
        if (result.isEmpty()) {
            throw new JwksClientException("JWKS response did not contain usable RSA keys");
        }
        return result;
    }

    private RSAPublicKey toPublicKey(final String modulus, final String exponent) {
        try {
            final byte[] nBytes = java.util.Base64.getUrlDecoder().decode(modulus);
            final byte[] eBytes = java.util.Base64.getUrlDecoder().decode(exponent);
            final BigInteger n = new BigInteger(1, nBytes);
            final BigInteger e = new BigInteger(1, eBytes);
            final RSAPublicKeySpec spec = new RSAPublicKeySpec(n, e);
            final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) keyFactory.generatePublic(spec);
        } catch (final IllegalArgumentException | NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new JwksClientException("Failed to build RSA public key", ex);
        }
    }
}
