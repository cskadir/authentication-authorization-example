package com.example.authentication_authorization_example.security.service;

import com.example.authentication_authorization_example.security.token.CustomAuthenticationToken;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthenticationService {
    public CustomAuthenticationToken authenticate(CustomAuthenticationToken customAuthenticationToken) {

        var username = ((String) customAuthenticationToken.getPrincipal());
        var password = ((String) customAuthenticationToken.getCredentials());

        if (username != null && password != null && username.startsWith("user") && password.equals("test")) {
            return new CustomAuthenticationToken(username, AuthorityUtils.createAuthorityList("ROLE_USER"));
        }

        throw new AuthenticationServiceException("Invalid username or password");

    }
}
