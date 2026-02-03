package com.sitionix.forge.security.server.core;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.util.StringUtils;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

public class MtlsServiceIdentityVerifier implements ServiceIdentityVerifier {

    @Override
    public ServiceIdentity verify(final HttpServletRequest request) {
        final X509Certificate certificate = this.extractCertificate(request);
        if (certificate == null) {
            throw new BadCredentialsException("Missing client certificate");
        }
        final String serviceName = this.extractServiceName(certificate);
        if (!StringUtils.hasText(serviceName)) {
            throw new BadCredentialsException("Client certificate missing service identity");
        }
        return new ServiceIdentity(serviceName, null, null, null, null, null, false);
    }

    private X509Certificate extractCertificate(final HttpServletRequest request) {
        Object attribute = request.getAttribute("jakarta.servlet.request.X509Certificate");
        if (attribute == null) {
            attribute = request.getAttribute("javax.servlet.request.X509Certificate");
        }
        if (!(attribute instanceof X509Certificate[] certificates) || certificates.length == 0) {
            return null;
        }
        return certificates[0];
    }

    private String extractServiceName(final X509Certificate certificate) {
        final String sanValue = this.extractSan(certificate);
        if (StringUtils.hasText(sanValue)) {
            return sanValue;
        }
        final X500Principal principal = certificate.getSubjectX500Principal();
        if (principal == null) {
            return null;
        }
        try {
            final LdapName ldapName = new LdapName(principal.getName());
            for (final Rdn rdn : ldapName.getRdns()) {
                if ("CN".equalsIgnoreCase(rdn.getType())) {
                    final Object value = rdn.getValue();
                    return value == null ? null : value.toString();
                }
            }
        } catch (final InvalidNameException ignored) {
            return null;
        }
        return null;
    }

    private String extractSan(final X509Certificate certificate) {
        try {
            final Collection<List<?>> sans = certificate.getSubjectAlternativeNames();
            if (sans == null) {
                return null;
            }
            for (final List<?> san : sans) {
                if (san == null || san.size() < 2) {
                    continue;
                }
                final Integer type = san.get(0) instanceof Integer ? (Integer) san.get(0) : null;
                final Object value = san.get(1);
                if (type == null || value == null) {
                    continue;
                }
                if (type == 2 || type == 1) {
                    return value.toString();
                }
            }
        } catch (final CertificateParsingException ignored) {
            return null;
        }
        return null;
    }
}
