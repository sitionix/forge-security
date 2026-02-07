package com.sitionix.forge.security.userjwt.web;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.sitionix.forge.security.userjwt.core.ForgeUser;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = ForgeUserJwtIntegrationTest.TestApplication.class)
@Import(ForgeUserJwtIntegrationTest.TestClockConfiguration.class)
class ForgeUserJwtIntegrationTest {

    private static MockWebServer server;
    private static RSAPublicKey publicKey;
    private static RSAPrivateKey privateKey;
    private static String jwksJson;
    private static String kid;
    private static TestClock testClock;
    private static AtomicInteger jwksRequests;

    static {
        try {
            final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            final KeyPair keyPair = generator.generateKeyPair();
            publicKey = (RSAPublicKey) keyPair.getPublic();
            privateKey = (RSAPrivateKey) keyPair.getPrivate();
            kid = "kid-1";
            testClock = new TestClock(Instant.parse("2024-01-01T00:00:00Z"), ZoneOffset.UTC);
            jwksRequests = new AtomicInteger();

            final byte[] modulusBytes = publicKey.getModulus().toByteArray();
            final byte[] modulusNormalized = modulusBytes.length > 1 && modulusBytes[0] == 0
                    ? Arrays.copyOfRange(modulusBytes, 1, modulusBytes.length)
                    : modulusBytes;
            final String modulusEncoded = Base64.getUrlEncoder().withoutPadding().encodeToString(modulusNormalized);

            final byte[] exponentBytes = publicKey.getPublicExponent().toByteArray();
            final byte[] exponentNormalized = exponentBytes.length > 1 && exponentBytes[0] == 0
                    ? Arrays.copyOfRange(exponentBytes, 1, exponentBytes.length)
                    : exponentBytes;
            final String exponentEncoded = Base64.getUrlEncoder().withoutPadding().encodeToString(exponentNormalized);

            jwksJson = "{" +
                    "\"keys\":[{" +
                    "\"kty\":\"RSA\"," +
                    "\"kid\":\"" + kid + "\"," +
                    "\"use\":\"sig\"," +
                    "\"alg\":\"RS256\"," +
                    "\"n\":\"" + modulusEncoded + "\"," +
                    "\"e\":\"" + exponentEncoded + "\"" +
                    "}]}";

            server = new MockWebServer();
            server.setDispatcher(new Dispatcher() {
                @Override
                public MockResponse dispatch(final RecordedRequest request) {
                    if (request.getPath() != null && request.getPath().endsWith("/.well-known/jwks.json")) {
                        jwksRequests.incrementAndGet();
                        return new MockResponse()
                                .setResponseCode(200)
                                .addHeader("Content-Type", "application/json")
                                .setBody(jwksJson);
                    }
                    return new MockResponse().setResponseCode(404);
                }
            });
            server.start();
            System.setProperty("forge.user-jwt.auth-base-url", server.url("/authsox/").toString());
            System.setProperty("forge.user-jwt.cache-ttl-seconds", "5");
        } catch (final IOException | NoSuchAlgorithmException ex) {
            throw new ExceptionInInitializerError(ex);
        }
    }

    @Autowired
    private TestRestTemplate restTemplate;

    @AfterAll
    static void shutdown() throws IOException {
        System.clearProperty("forge.user-jwt.auth-base-url");
        System.clearProperty("forge.user-jwt.cache-ttl-seconds");
        server.shutdown();
    }

    @Test
    void givenMissingToken_whenAccessProtected_thenUnauthorized() {
        //given
        final String url = "/protected";

        //when
        final ResponseEntity<String> response = this.restTemplate.getForEntity(url, String.class);

        //then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void givenValidToken_whenAccessProtected_thenCachesJwks() {
        //given
        final Instant now = testClock.instant();
        final String token = JWT.create()
                .withKeyId(kid)
                .withSubject("user-123")
                .withIssuer("auth-service")
                .withIssuedAt(Date.from(now.minusSeconds(5)))
                .withExpiresAt(Date.from(now.plusSeconds(3600)))
                .sign(Algorithm.RSA256(publicKey, privateKey));
        final HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        jwksRequests.set(0);

        //when
        final ResponseEntity<String> first = this.restTemplate.exchange("/protected", HttpMethod.GET,
                new HttpEntity<>(headers), String.class);
        final ResponseEntity<String> second = this.restTemplate.exchange("/protected", HttpMethod.GET,
                new HttpEntity<>(headers), String.class);
        testClock.advance(Duration.ofSeconds(6));
        final ResponseEntity<String> third = this.restTemplate.exchange("/protected", HttpMethod.GET,
                new HttpEntity<>(headers), String.class);

        //then
        assertThat(first.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(first.getBody()).contains("\"subject\":\"user-123\"");
        assertThat(first.getBody()).contains("\"name\":\"user-123\"");
        assertThat(second.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(third.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(jwksRequests.get()).isEqualTo(2);
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
    }

    @TestConfiguration
    static class TestClockConfiguration {
        @Bean
        TestClock testClock() {
            return testClock;
        }
    }

    static class TestClock extends Clock {

        private Instant instant;
        private final ZoneId zone;

        TestClock(final Instant instant, final ZoneId zone) {
            this.instant = instant;
            this.zone = zone;
        }

        void advance(final Duration duration) {
            this.instant = this.instant.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return this.zone;
        }

        @Override
        public Clock withZone(final ZoneId zone) {
            return new TestClock(this.instant, zone);
        }

        @Override
        public Instant instant() {
            return this.instant;
        }
    }
}
