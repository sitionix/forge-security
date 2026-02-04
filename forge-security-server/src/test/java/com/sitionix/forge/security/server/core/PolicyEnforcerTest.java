package com.sitionix.forge.security.server.core;

import com.sitionix.forge.security.server.config.ForgeSecurityServerProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PolicyEnforcerTest {

    @Mock
    private ForgeSecurityServerProperties properties;

    private PolicyEnforcer policyEnforcer;

    @BeforeEach
    void setUp() {
        this.policyEnforcer = new PolicyEnforcer(this.properties);
    }

    @AfterEach
    void tearDown() {
        verifyNoMoreInteractions(this.properties);
    }

    @Test
    void givenPolicyDeniesEndpoint_whenAssertAllowed_thenThrowsAccessDeniedException() {
        //given
        final ServiceIdentity identity = this.getIdentity("sitionix.bff");
        final Map<String, ForgeSecurityServerProperties.Policy> policies = new HashMap<>();
        policies.put("sitionix.bff", this.getPolicy(List.of("GET /allowed")));
        when(this.properties.getPolicies()).thenReturn(policies);

        //when
        assertThatThrownBy(() -> this.policyEnforcer.assertAllowed(identity, "POST", "/denied"))
                .isInstanceOf(AccessDeniedException.class);

        //then
        verify(this.properties).getPolicies();
    }

    private ForgeSecurityServerProperties.Policy getPolicy(final List<String> allow) {
        final ForgeSecurityServerProperties.Policy policy = new ForgeSecurityServerProperties.Policy();
        policy.setAllow(allow);
        return policy;
    }

    private ServiceIdentity getIdentity(final String serviceName) {
        return new ServiceIdentity(serviceName,
                List.of(),
                Instant.now(),
                Instant.now().plusSeconds(300),
                "sitionix-internal",
                "sitionix.auth",
                false);
    }
}
