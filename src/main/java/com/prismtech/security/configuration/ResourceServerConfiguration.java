package com.prismtech.security.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class ResourceServerConfiguration {
    @Bean
    @Order(1)
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.mvcMatcher("/resource-apis/**")
                .authorizeRequests()
                .mvcMatchers("/resource-apis/articles-system")
                .hasAnyAuthority("SCOPE_system.read")
                .mvcMatchers("/resource-apis/articles-user")
                .hasAnyAuthority("SCOPE_user.read")
                .and()
                .oauth2ResourceServer()
                .jwt();
        return http.build();
    }
}
