package com.sitionix.forge.security.server.web;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK,
        classes = ForgeSecurityServerIntegrationTest.TestApplication.class,
        properties = {
                "server.servlet.context-path=/stsssox",
                "forge.security.service-id=sitionixSite",
                "forge.security.dev.jwt-secret=test-internal-secret",
                "forge.security.dev.issuer=sitionix-internal",
                "forge.security.server.excludes[0]=/actuator/health",
                "forge.security.server.excludes[1]=/actuator/health/readiness",
                "forge.security.server.excludes[2]=/actuator/health/liveness"
        })
@AutoConfigureMockMvc
class ForgeSecurityServerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void givenExcludedHealthEndpointWithoutServiceJwt_whenAccess_thenReturnsOk() throws Exception {
        //given
        final String url = "/stsssox/actuator/health/readiness";

        //when
        final MvcResult response = this.mockMvc.perform(MockMvcRequestBuilders.get(url)
                        .contextPath("/stsssox"))
                .andReturn();

        //then
        assertThat(response.getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());
        assertThat(response.getResponse().getContentAsString()).isEqualTo("UP");
    }

    @Test
    void givenProtectedEndpointWithoutServiceJwt_whenAccess_thenReturnsForbidden() throws Exception {
        //given
        final String url = "/stsssox/protected";

        //when
        final MvcResult response = this.mockMvc.perform(MockMvcRequestBuilders.get(url)
                        .contextPath("/stsssox"))
                .andReturn();

        //then
        assertThat(response.getResponse().getStatus()).isEqualTo(HttpStatus.FORBIDDEN.value());
    }

    @SpringBootApplication
    @Import(TestController.class)
    static class TestApplication {
    }

    @RestController
    static class TestController {

        @GetMapping("/actuator/health/readiness")
        ResponseEntity<String> readiness() {
            return ResponseEntity.ok("UP");
        }

        @GetMapping("/protected")
        ResponseEntity<String> protectedEndpoint() {
            return ResponseEntity.ok("protected");
        }
    }
}
