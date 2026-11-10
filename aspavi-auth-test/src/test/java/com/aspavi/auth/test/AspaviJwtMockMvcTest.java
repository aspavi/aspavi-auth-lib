package com.aspavi.auth.test;

import com.aspavi.auth.security.CurrentUser;
import com.aspavi.auth.security.KeycloakRealmRoleConverter;
import com.aspavi.auth.security.TenantFilter;
import com.aspavi.auth.tenant.TenantContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.junit.jupiter.web.SpringJUnitWebConfig;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.util.UUID;
import java.util.stream.Collectors;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end check of {@link AspaviJwt} against a security setup like the services':
 * stateless resource server, {@code TenantFilter}, method security with {@code hasAuthority}
 * and {@code CurrentUser}.
 */
@SpringJUnitWebConfig(AspaviJwtMockMvcTest.WebConfig.class)
class AspaviJwtMockMvcTest {

    private static final String BEARER_TOKEN = "employee-read-token";
    private static final UUID EMPLOYEE = UUID.fromString("7c9e6679-7425-40de-944b-e07fc1f90ae7");

    @Autowired
    private WebApplicationContext context;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    @Test
    void grantsAccessWithTheRequiredPermission() throws Exception {
        mockMvc.perform(get("/employees").with(AspaviJwt.withPermissions("employee:read").tenantId("acme")))
                .andExpect(status().isOk())
                .andExpect(content().string("employees of acme"));
    }

    @Test
    void deniesAccessWithoutTheRequiredPermission() throws Exception {
        mockMvc.perform(get("/employees").with(AspaviJwt.withPermissions("employee:write")))
                .andExpect(status().isForbidden());
    }

    @Test
    void bareSpringJwtIsDeniedBecauseItOnlyGrantsScopeAuthorities() throws Exception {
        mockMvc.perform(get("/employees").with(jwt()))
                .andExpect(status().isForbidden());
    }

    @Test
    void unauthenticatedRequestIsRejected() throws Exception {
        mockMvc.perform(get("/employees"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void meEndpointResolvesTheEmployeeFromTheToken() throws Exception {
        mockMvc.perform(get("/me").with(AspaviJwt.withPermissions().employeeId(EMPLOYEE)))
                .andExpect(status().isOk())
                .andExpect(content().string(EMPLOYEE.toString()));
    }

    @Test
    void meEndpointIsForbiddenWhenTheTokenHasNoEmployee() throws Exception {
        mockMvc.perform(get("/me").with(AspaviJwt.withPermissions()))
                .andExpect(status().isForbidden());
    }

    @Test
    void realBearerTokenGetsRealmRolesPlusSpringSecurityFactorAuthority() throws Exception {
        mockMvc.perform(get("/employees").header("Authorization", "Bearer " + BEARER_TOKEN))
                .andExpect(status().isOk());

        mockMvc.perform(get("/authorities").header("Authorization", "Bearer " + BEARER_TOKEN))
                .andExpect(status().isOk())
                .andExpect(content().string("FACTOR_BEARER,employee:read"));
    }

    @Configuration(proxyBeanMethods = false)
    @EnableWebMvc
    @EnableWebSecurity
    @EnableMethodSecurity
    static class WebConfig {

        @Bean
        JwtDecoder jwtDecoder() {
            return token -> {
                if (BEARER_TOKEN.equals(token)) {
                    return AspaviJwt.withPermissions("employee:read").toJwt();
                }
                throw new JwtException("Unknown test token");
            };
        }

        @Bean
        JwtAuthenticationConverter jwtAuthenticationConverter() {
            JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
            converter.setJwtGrantedAuthoritiesConverter(new KeycloakRealmRoleConverter());
            return converter;
        }

        @Bean
        SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
            http
                    .csrf(csrf -> csrf.disable())
                    .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                    .authorizeHttpRequests(authz -> authz.anyRequest().authenticated())
                    .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> {}))
                    .addFilterAfter(new TenantFilter(), BearerTokenAuthenticationFilter.class);
            return http.build();
        }

        @Bean
        TestController testController() {
            return new TestController();
        }
    }

    @RestController
    static class TestController {

        @GetMapping("/employees")
        @PreAuthorize("hasAuthority('employee:read')")
        public String employees() {
            return "employees of " + TenantContext.getRequiredTenantId();
        }

        @GetMapping("/authorities")
        public String authorities(Authentication authentication) {
            return authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .sorted()
                    .collect(Collectors.joining(","));
        }

        @GetMapping("/me")
        public String me() {
            return CurrentUser.requireEmployeeId().toString();
        }
    }
}
