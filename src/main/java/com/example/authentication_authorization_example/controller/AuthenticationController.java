package com.example.authentication_authorization_example.controller;

import com.example.authentication_authorization_example.dto.LoginRequest;
import com.example.authentication_authorization_example.security.service.CustomAuthenticationService;
import com.example.authentication_authorization_example.security.token.CustomAuthenticationToken;
import com.example.authentication_authorization_example.security.util.JWTUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    private final JWTUtil jwtUtil;
    private  final AuthenticationManager  authenticationManager;

    public AuthenticationController(JWTUtil jwtUtil, AuthenticationManager authenticationManager) {
        this.jwtUtil = jwtUtil;
        this.authenticationManager = authenticationManager;
    }


    @PostMapping("/login")
    public ResponseEntity<Void> authenticate(HttpServletResponse response, @RequestBody LoginRequest loginRequest) {

        var customAuthenticationToken = new CustomAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword());

        var authenticate =  authenticationManager.authenticate(customAuthenticationToken);


        var cookie = jwtUtil.generateJwtCookie((CustomAuthenticationToken) authenticate);
        response.setHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        return ResponseEntity.ok().build();
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletResponse response) {

        Cookie clearCookie = jwtUtil.generateCookieForClearingFromBrowser();
        response.addCookie(clearCookie);

        return ResponseEntity.ok().build();
    }


}
