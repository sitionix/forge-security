package com.sitionix.forge.security.userjwt.client;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@ExtendWith(MockitoExtension.class)
class JwksEndpointTest {

    @Test
    void givenNullPath_whenFromPath_thenReturnsCanonical() {
        //given
        final String path = null;

        //when
        final JwksEndpoint endpoint = JwksEndpoint.fromPath(path);

        //then
        assertThat(endpoint).isEqualTo(JwksEndpoint.CANONICAL);
    }

    @Test
    void givenCanonicalPath_whenFromPath_thenReturnsCanonical() {
        //given
        final String path = "/.well-known/jwks.json";

        //when
        final JwksEndpoint endpoint = JwksEndpoint.fromPath(path);

        //then
        assertThat(endpoint).isEqualTo(JwksEndpoint.CANONICAL);
    }

    @Test
    void givenAliasPathWithoutLeadingSlash_whenFromPath_thenReturnsAlias() {
        //given
        final String path = "oauth2/v1/keys";

        //when
        final JwksEndpoint endpoint = JwksEndpoint.fromPath(path);

        //then
        assertThat(endpoint).isEqualTo(JwksEndpoint.ALIAS);
    }

    @Test
    void givenUnsupportedPath_whenFromPath_thenThrows() {
        //given
        final String path = "/custom/jwks";

        //when
        //then
        assertThatThrownBy(() -> JwksEndpoint.fromPath(path))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
