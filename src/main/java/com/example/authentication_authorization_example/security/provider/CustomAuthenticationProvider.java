package com.example.authentication_authorization_example.security.provider;

import com.example.authentication_authorization_example.security.service.CustomAuthenticationService;
import com.example.authentication_authorization_example.security.token.CustomAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final CustomAuthenticationService customAuthenticationService;

    public CustomAuthenticationProvider(CustomAuthenticationService customAuthenticationService) {
        this.customAuthenticationService = customAuthenticationService;
    }


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        return customAuthenticationService.authenticate((CustomAuthenticationToken) authentication);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return CustomAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
