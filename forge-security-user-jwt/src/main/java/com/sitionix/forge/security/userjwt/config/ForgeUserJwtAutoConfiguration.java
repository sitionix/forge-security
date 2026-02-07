package com.sitionix.forge.security.userjwt.config;

import com.app_afesox.athssox.client.api.SecurityApi;
import com.app_afesox.athssox.client.invoker.ApiClient;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sitionix.forge.security.userjwt.client.AthssoxJwksClient;
import com.sitionix.forge.security.userjwt.client.JwkRsaKeyConverter;
import com.sitionix.forge.security.userjwt.client.JwksClient;
import com.sitionix.forge.security.userjwt.client.JwksEndpoint;
import com.sitionix.forge.security.userjwt.core.JwksCache;
import com.sitionix.forge.security.userjwt.core.UserJwtVerifier;
import com.sitionix.forge.security.userjwt.web.ForgeUserJwtAccessDeniedHandler;
import com.sitionix.forge.security.userjwt.web.ForgeUserJwtAuthenticationEntryPoint;
import com.sitionix.forge.security.userjwt.web.ForgeUserJwtFilter;
import com.sitionix.forge.security.userjwt.web.CurrentForgeUser;
import com.sitionix.forge.security.userjwt.web.SecurityContextCurrentForgeUser;
import com.sitionix.forge.security.userjwt.web.UserJwtErrorResponseWriter;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.util.Timeout;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.BufferingClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.web.client.RestTemplate;

import java.time.Clock;
import java.time.Duration;

@AutoConfiguration
@ConditionalOnClass({HttpSecurity.class, RestTemplate.class})
@EnableConfigurationProperties(ForgeUserJwtProperties.class)
@EnableMethodSecurity
public class ForgeUserJwtAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public Clock forgeUserJwtClock() {
        return Clock.systemUTC();
    }

    @Bean
    @ConditionalOnMissingBean
    public ObjectMapper forgeUserJwtObjectMapper() {
        return new ObjectMapper();
    }

    @Bean(name = "forgeUserJwtRestTemplate")
    @ConditionalOnMissingBean(name = "forgeUserJwtRestTemplate")
    public RestTemplate forgeUserJwtRestTemplate(final ForgeUserJwtProperties properties) {
        final RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(Timeout.ofMilliseconds(properties.getConnectTimeoutMs()))
                .setResponseTimeout(Timeout.ofMilliseconds(properties.getReadTimeoutMs()))
                .build();
        final HttpComponentsClientHttpRequestFactory requestFactory =
                new HttpComponentsClientHttpRequestFactory(HttpClients.custom()
                        .setDefaultRequestConfig(requestConfig)
                        .build());
        requestFactory.setConnectionRequestTimeout(properties.getConnectTimeoutMs());
        return new RestTemplate(new BufferingClientHttpRequestFactory(requestFactory));
    }

    @Bean
    @ConditionalOnMissingBean
    public ApiClient forgeUserJwtApiClient(
            @Qualifier("forgeUserJwtRestTemplate") final RestTemplate forgeUserJwtRestTemplate,
            final ForgeUserJwtProperties properties) {
        final ApiClient apiClient = new ApiClient(forgeUserJwtRestTemplate);
        apiClient.setBasePath(this.normalizeBasePath(properties.getAuthBaseUrl()));
        apiClient.addDefaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
        apiClient.addDefaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        return apiClient;
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityApi forgeUserJwtSecurityApi(final ApiClient forgeUserJwtApiClient) {
        return new SecurityApi(forgeUserJwtApiClient);
    }

    @Bean
    @ConditionalOnMissingBean
    public JwksEndpoint forgeUserJwtJwksEndpoint(final ForgeUserJwtProperties properties) {
        return JwksEndpoint.fromPath(properties.getJwksPath());
    }

    @Bean
    @ConditionalOnMissingBean
    public JwkRsaKeyConverter forgeUserJwtKeyConverter() {
        return new JwkRsaKeyConverter();
    }

    @Bean
    @ConditionalOnMissingBean
    public JwksClient forgeUserJwtJwksClient(final SecurityApi forgeUserJwtSecurityApi,
                                             final JwkRsaKeyConverter forgeUserJwtKeyConverter,
                                             final JwksEndpoint forgeUserJwtJwksEndpoint) {
        return new AthssoxJwksClient(forgeUserJwtSecurityApi, forgeUserJwtKeyConverter,
                forgeUserJwtJwksEndpoint);
    }

    @Bean
    public JwksCache forgeUserJwtJwksCache(final JwksClient forgeUserJwtJwksClient,
                                           final ForgeUserJwtProperties properties,
                                           final Clock forgeUserJwtClock) {
        return new JwksCache(forgeUserJwtJwksClient, Duration.ofSeconds(properties.getCacheTtlSeconds()),
                forgeUserJwtClock);
    }

    @Bean
    public UserJwtVerifier forgeUserJwtVerifier(final JwksCache forgeUserJwtJwksCache,
                                                final ForgeUserJwtProperties properties,
                                                final Clock forgeUserJwtClock) {
        return new UserJwtVerifier(forgeUserJwtJwksCache, properties, forgeUserJwtClock);
    }

    @Bean
    public UserJwtErrorResponseWriter forgeUserJwtErrorResponseWriter(
            final ObjectMapper forgeUserJwtObjectMapper) {
        return new UserJwtErrorResponseWriter(forgeUserJwtObjectMapper);
    }

    @Bean
    public ForgeUserJwtFilter forgeUserJwtFilter(final UserJwtVerifier forgeUserJwtVerifier,
                                                 final UserJwtErrorResponseWriter forgeUserJwtErrorResponseWriter) {
        return new ForgeUserJwtFilter(forgeUserJwtVerifier, forgeUserJwtErrorResponseWriter);
    }

    @Bean
    public FilterRegistrationBean<ForgeUserJwtFilter> forgeUserJwtFilterRegistration(
            final ForgeUserJwtFilter forgeUserJwtFilter) {
        final FilterRegistrationBean<ForgeUserJwtFilter> registration =
                new FilterRegistrationBean<>(forgeUserJwtFilter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    @ConditionalOnMissingBean(AuthenticationEntryPoint.class)
    public AuthenticationEntryPoint forgeUserJwtAuthenticationEntryPoint(
            final UserJwtErrorResponseWriter forgeUserJwtErrorResponseWriter) {
        return new ForgeUserJwtAuthenticationEntryPoint(forgeUserJwtErrorResponseWriter);
    }

    @Bean
    @ConditionalOnMissingBean(AccessDeniedHandler.class)
    public AccessDeniedHandler forgeUserJwtAccessDeniedHandler(
            final UserJwtErrorResponseWriter forgeUserJwtErrorResponseWriter) {
        return new ForgeUserJwtAccessDeniedHandler(forgeUserJwtErrorResponseWriter);
    }

    @Bean
    @ConditionalOnMissingBean
    public CurrentForgeUser currentForgeUser() {
        return new SecurityContextCurrentForgeUser();
    }

    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain forgeUserJwtFilterChain(final HttpSecurity http,
                                                       final ForgeUserJwtFilter forgeUserJwtFilter,
                                                       final ObjectProvider<AuthenticationEntryPoint> entryPointProvider,
                                                       final ObjectProvider<AccessDeniedHandler> accessDeniedHandlerProvider)
            throws Exception {
        final AuthenticationEntryPoint entryPoint = entryPointProvider.getIfAvailable();
        final AccessDeniedHandler accessDeniedHandler = accessDeniedHandlerProvider.getIfAvailable();

        http.csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll())
                .addFilterBefore(forgeUserJwtFilter, AuthorizationFilter.class);

        if (entryPoint != null || accessDeniedHandler != null) {
            http.exceptionHandling(exceptionHandling -> {
                if (entryPoint != null) {
                    exceptionHandling.authenticationEntryPoint(entryPoint);
                }
                if (accessDeniedHandler != null) {
                    exceptionHandling.accessDeniedHandler(accessDeniedHandler);
                }
            });
        }

        return http.build();
    }

    @Bean
    public ForgeUserJwtValidator forgeUserJwtValidator(final ForgeUserJwtProperties properties) {
        return new ForgeUserJwtValidator(properties);
    }

    private String normalizeBasePath(final String basePath) {
        if (basePath == null) {
            return null;
        }
        String normalized = basePath.trim();
        while (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }
}
