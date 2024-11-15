package com.example.authentication_authorization_example.security;

import com.example.authentication_authorization_example.security.filter.AuthorizationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@EnableWebSecurity
@Configuration
public class WebSecurityConfiguration {

    private final AuthorizationFilter authorizationFilter;
    private final AuthenticationProvider authenticationProvider;

    public WebSecurityConfiguration(AuthorizationFilter authorizationFilter, AuthenticationProvider authenticationProvider) {
        this.authorizationFilter = authorizationFilter;
        this.authenticationProvider = authenticationProvider;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .formLogin(AbstractHttpConfigurer::disable)
                .sessionManagement(sessionManagementConfigurer ->
                        sessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .cors(cors -> cors
                        .configurationSource(corsConfiguration())
                )
                .csrf(AbstractHttpConfigurer::disable)
                .headers(httpSecurityHeadersConfigurer ->
                        httpSecurityHeadersConfigurer
                                .frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin)
                                .xssProtection(xXssConfig ->
                                        xXssConfig.headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED))
                )
                .authorizeHttpRequests(requests -> {
                    requests.requestMatchers("/auth/login").permitAll();
                    requests.requestMatchers("/index.html").permitAll();
                    requests.requestMatchers("/js/script.js").permitAll();
                    requests.requestMatchers("/favicon.ico").permitAll();
                    requests.anyRequest().authenticated();
                })
                .addFilterBefore(authorizationFilter,
                        org.springframework.security.web.access.intercept.AuthorizationFilter.class);
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(authenticationProvider);
    }

    private CorsConfigurationSource corsConfiguration() {
        var configuration = new CorsConfiguration();
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowedOriginPatterns(List.of("*"));
        configuration.setAllowCredentials(true);
        configuration.setAllowedMethods(List.of(HttpMethod.GET.name(), HttpMethod.POST.name(),
                HttpMethod.DELETE.name(), HttpMethod.PUT.name()));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
