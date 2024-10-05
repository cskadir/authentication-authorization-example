package com.example.authentication_authorization_example.controller;

import com.example.authentication_authorization_example.dto.LoginRequest;
import com.example.authentication_authorization_example.security.util.Constant;
import com.example.authentication_authorization_example.security.util.JWTUtil;
import com.example.authentication_authorization_example.service.AuthenticationService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final JWTUtil jwtUtil;
    private final UserDetailsService userDetailsService;

    public AuthenticationController(AuthenticationService authenticationService, JWTUtil jwtUtil, @Qualifier("userDetailsService") UserDetailsService userDetailsService) {
        this.authenticationService = authenticationService;
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }


    @PostMapping("/login")
    public ResponseEntity<Void> authenticate(HttpServletResponse response, @RequestBody LoginRequest loginRequest) {

        UserDetails userDetails = authenticationService.login(loginRequest);
        var jwt = jwtUtil.generateJwtToken(userDetails);
        response.setHeader(HttpHeaders.SET_COOKIE, Constant.COOKIE_NAME + "=" + jwt);
        return ResponseEntity.ok().build();
    }

}
