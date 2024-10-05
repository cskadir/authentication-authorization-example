package com.example.authentication_authorization_example.security.filter;

import com.example.authentication_authorization_example.security.util.Constant;
import com.example.authentication_authorization_example.security.util.JWTUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Objects;

@Component
public class AuthorizationFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    public AuthorizationFilter(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String jwt = jwtUtil.getJwtFromCookies(request, Constant.COOKIE_NAME);
        if (Objects.nonNull(jwt)) {
            if (jwtUtil.isTokenValid(jwt)) {
                var username = jwtUtil.extractUsername(jwt);
                var simpleGrantedAuthorities = jwtUtil.extractRoles(jwt);
                SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(username, null, simpleGrantedAuthorities));
            }
        }
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return request.getRequestURI().contains(Constant.LOGIN_PATH);
    }
}
