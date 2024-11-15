package com.example.authentication_authorization_example.security.token;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.List;

public class CustomAuthenticationToken implements Authentication {

    private boolean authenticated;
    private String username;
    private String password;
    private List<GrantedAuthority> authorities;

    public CustomAuthenticationToken(String username, String password) {
        this.password = password;
        this.username = username;
        authenticated = false;
    }

    public CustomAuthenticationToken(String username, List<GrantedAuthority> authorities) {
        this.username = username;
        this.authorities = authorities;
        this.authenticated = true;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public Object getCredentials() {
        return password;
    }

    @Override
    public Object getDetails() {
        return this;
    }

    @Override
    public Object getPrincipal() {
        return username;
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {

    }

    @Override
    public String getName() {
        return "";
    }


}
