package com.sitionix.forge.security.client.core;

import com.sitionix.forge.security.client.config.ForgeSecurityClientProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ServiceIdResolverTest {

    @Mock
    private ForgeSecurityClientProperties properties;

    private ServiceIdResolver serviceIdResolver;

    @BeforeEach
    void setUp() {
        final Map<String, ForgeSecurityClientProperties.TargetDefinition> targets = new HashMap<>();
        targets.put("sitionix.auth", this.getTargetDefinition("auth-service"));
        targets.put("sitionix.bff", this.getTargetDefinition("bff-service"));
        when(this.properties.getTargets()).thenReturn(targets);

        this.serviceIdResolver = new ServiceIdResolver(this.properties);
    }

    @AfterEach
    void tearDown() {
        verify(this.properties).getTargets();
        verifyNoMoreInteractions(this.properties);
    }

    @Test
    void givenKnownHost_whenResolveServiceId_thenReturnsLogicalId() {
        //given
        final String host = "auth-service";

        //when
        final String result = this.serviceIdResolver.resolveServiceId(host);

        //then
        assertThat(result).isEqualTo("sitionix.auth");
    }

    @Test
    void givenHostWithPort_whenResolveServiceId_thenReturnsLogicalId() {
        //given
        final String host = "auth-service:9090";

        //when
        final String result = this.serviceIdResolver.resolveServiceId(host);

        //then
        assertThat(result).isEqualTo("sitionix.auth");
    }

    @Test
    void givenUnknownHost_whenResolveServiceId_thenReturnsNull() {
        //given
        final String host = "unknown-service";

        //when
        final String result = this.serviceIdResolver.resolveServiceId(host);

        //then
        assertThat(result).isNull();
    }

    @Test
    void givenUrl_whenResolveServiceId_thenReturnsLogicalId() {
        //given
        final String url = "http://auth-service:9090/authsox";

        //when
        final String result = this.serviceIdResolver.resolveServiceId(url);

        //then
        assertThat(result).isEqualTo("sitionix.auth");
    }

    private ForgeSecurityClientProperties.TargetDefinition getTargetDefinition(final String host) {
        final ForgeSecurityClientProperties.TargetDefinition definition =
                new ForgeSecurityClientProperties.TargetDefinition();
        definition.setHost(host);
        return definition;
    }
}
