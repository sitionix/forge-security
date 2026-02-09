package com.sitionix.forge.security.userjwt.web;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.sitionix.forge.security.userjwt.client.JwksClient;
import com.sitionix.forge.security.userjwt.core.ForgeUser;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK,
        classes = ForgeUserJwtIntegrationTest.TestApplication.class,
        properties = {
                "forge.user-jwt.cache-ttl-seconds=5",
                "forge.user-jwt.issuer=auth-service",
                "forge.user-jwt.auth-base-url=http://auth.local"
        })
@AutoConfigureMockMvc
@Import(ForgeUserJwtIntegrationTest.TestSupportConfiguration.class)
class ForgeUserJwtIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private TestKeyMaterial keyMaterial;

    @Test
    void givenMissingToken_whenAccessProtected_thenUnauthorized() throws Exception {
        //given
        final String url = "/protected";

        //when
        final MvcResult response = this.mockMvc.perform(MockMvcRequestBuilders.get(url))
                .andReturn();

        //then
        assertThat(response.getResponse().getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
    }

    @Test
    void givenValidToken_whenAccessProtected_thenReturnsUserResponse() throws Exception {
        //given
        final Instant now = Instant.now();
        final String token = this.keyMaterial.issueUserToken(this.keyMaterial.getKid(),
                now.minusSeconds(5), now.plusSeconds(3600));

        //when
        final MvcResult first = this.mockMvc.perform(MockMvcRequestBuilders.get("/protected")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andReturn();
        final MvcResult second = this.mockMvc.perform(MockMvcRequestBuilders.get("/protected")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andReturn();

        //then
        assertThat(first.getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());
        assertThat(first.getResponse().getContentAsString()).contains("\"subject\":\"user-123\"");
        assertThat(first.getResponse().getContentAsString()).contains("\"name\":\"user-123\"");
        assertThat(second.getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());
    }

    @Test
    void givenNoAuthorization_whenPostVerifyEmail_thenOk() throws Exception {
        //given
        final String url = "/api/v1/auth/email/verify";

        //when
        final MvcResult response = this.mockMvc.perform(MockMvcRequestBuilders.post(url))
                .andReturn();

        //then
        assertThat(response.getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());
        assertThat(response.getResponse().getContentAsString()).isEqualTo("ok");
    }

    @Test
    void givenValidUserJwt_whenPostVerifyEmail_thenOk() throws Exception {
        //given
        final Instant now = Instant.now();
        final String token = this.keyMaterial.issueUserToken(this.keyMaterial.getKid(),
                now.minusSeconds(5), now.plusSeconds(3600));
        final String url = "/api/v1/auth/email/verify";

        //when
        final MvcResult response = this.mockMvc.perform(MockMvcRequestBuilders.post(url)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andReturn();

        //then
        assertThat(response.getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());
        assertThat(response.getResponse().getContentAsString()).isEqualTo("ok");
    }

    @Test
    void givenInvalidUserJwt_whenPostVerifyEmail_thenUnauthorized() throws Exception {
        //given
        final Instant now = Instant.now();
        final String token = this.keyMaterial.issueUserToken("kid-unknown",
                now.minusSeconds(5), now.plusSeconds(3600));
        final String url = "/api/v1/auth/email/verify";

        //when
        final MvcResult response = this.mockMvc.perform(MockMvcRequestBuilders.post(url)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andReturn();

        //then
        assertThat(response.getResponse().getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
    }

    @Test
    void givenServiceJwt_whenPostVerifyEmail_thenOk() throws Exception {
        //given
        final String token = this.keyMaterial.issueServiceToken();
        final String url = "/api/v1/auth/email/verify";

        //when
        final MvcResult response = this.mockMvc.perform(MockMvcRequestBuilders.post(url)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andReturn();

        //then
        assertThat(response.getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());
        assertThat(response.getResponse().getContentAsString()).isEqualTo("ok");
    }

    @Test
    void givenGarbageBearer_whenPostVerifyEmail_thenOk() throws Exception {
        //given
        final String url = "/api/v1/auth/email/verify";

        //when
        final MvcResult response = this.mockMvc.perform(MockMvcRequestBuilders.post(url)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer not-a-jwt"))
                .andReturn();

        //then
        assertThat(response.getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());
        assertThat(response.getResponse().getContentAsString()).isEqualTo("ok");
    }

    @Test
    void givenServiceJwt_whenAccessProtected_thenUnauthorized() throws Exception {
        //given
        final String token = this.keyMaterial.issueServiceToken();
        final String url = "/protected";

        //when
        final MvcResult response = this.mockMvc.perform(MockMvcRequestBuilders.get(url)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andReturn();

        //then
        assertThat(response.getResponse().getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
    }

    @Test
    void givenInvalidUserJwt_whenAccessProtected_thenUnauthorized() throws Exception {
        //given
        final Instant now = Instant.now();
        final String token = this.keyMaterial.issueUserToken("kid-unknown",
                now.minusSeconds(5), now.plusSeconds(3600));
        final String url = "/protected";

        //when
        final MvcResult response = this.mockMvc.perform(MockMvcRequestBuilders.get(url)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andReturn();

        //then
        assertThat(response.getResponse().getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
    }

    @SpringBootApplication
    @Import(TestController.class)
    static class TestApplication {
    }

    @RestController
    static class TestController {
        @GetMapping("/protected")
        @PreAuthorize("isAuthenticated()")
        Map<String, String> protectedEndpoint(final Authentication authentication) {
            final ForgeUser user = (ForgeUser) authentication.getPrincipal();
            return Map.of("subject", user.getSubject(),
                    "name", authentication.getName());
        }

        @PostMapping("/api/v1/auth/email/verify")
        ResponseEntity<String> verifyEmail() {
            return ResponseEntity.ok("ok");
        }
    }

    @TestConfiguration
    static class TestSupportConfiguration {

        @Bean
        TestKeyMaterial testKeyMaterial() {
            return new TestKeyMaterial();
        }

        @Bean
        JwksClient jwksClient(final TestKeyMaterial keyMaterial) {
            return () -> Map.of(keyMaterial.getKid(), keyMaterial.getPublicKey());
        }
    }

    static class TestKeyMaterial {

        private final RSAPublicKey publicKey;
        private final RSAPrivateKey privateKey;
        private final String kid;

        TestKeyMaterial() {
            this.kid = "kid-1";
            try {
                final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
                generator.initialize(2048);
                final KeyPair keyPair = generator.generateKeyPair();
                this.publicKey = (RSAPublicKey) keyPair.getPublic();
                this.privateKey = (RSAPrivateKey) keyPair.getPrivate();
            } catch (final NoSuchAlgorithmException ex) {
                throw new IllegalStateException("Unable to generate RSA key pair", ex);
            }
        }

        RSAPublicKey getPublicKey() {
            return this.publicKey;
        }

        String getKid() {
            return this.kid;
        }

        String issueUserToken(final String tokenKid, final Instant issuedAt, final Instant expiresAt) {
            return JWT.create()
                    .withKeyId(tokenKid)
                    .withSubject("user-123")
                    .withIssuer("auth-service")
                    .withIssuedAt(Date.from(issuedAt))
                    .withExpiresAt(Date.from(expiresAt))
                    .sign(Algorithm.RSA256(this.publicKey, this.privateKey));
        }

        String issueServiceToken() {
            return JWT.create()
                    .withSubject("service-123")
                    .sign(Algorithm.HMAC256("service-secret"));
        }
    }

}
