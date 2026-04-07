package com.sitionix.forge.security.server.config;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ForgeSecurityServerValidatorTest {

    @Test
    void givenExactExcludePath_whenValidate_thenDoesNotThrowException() {
        //given
        final ForgeSecurityServerProperties properties = this.getProperties();
        properties.getServer().setExcludes(java.util.List.of("/actuator/health/readiness"));
        final ForgeSecurityServerValidator validator = new ForgeSecurityServerValidator(properties);

        //when
        final org.assertj.core.api.ThrowableAssert.ThrowingCallable callable = validator::validate;

        //then
        assertThatCode(callable).doesNotThrowAnyException();
    }

    @Test
    void givenPatternExcludePath_whenValidate_thenThrowsIllegalStateException() {
        //given
        final ForgeSecurityServerProperties properties = this.getProperties();
        properties.getServer().setExcludes(java.util.List.of("/**"));
        final ForgeSecurityServerValidator validator = new ForgeSecurityServerValidator(properties);

        //when
        final org.assertj.core.api.ThrowableAssert.ThrowingCallable callable = validator::validate;

        //then
        assertThatThrownBy(callable)
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Invalid forge.security.server.excludes entry: /**");
    }

    private ForgeSecurityServerProperties getProperties() {
        final ForgeSecurityServerProperties properties = new ForgeSecurityServerProperties();
        properties.setServiceId("sitionixSite");
        properties.getDev().setJwtSecret("test-internal-secret");
        properties.getDev().setIssuer("sitionix-internal");
        properties.getDev().setTtlSeconds(300);
        return properties;
    }
}
