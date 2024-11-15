package com.example.authentication_authorization_example.security.util;

import com.example.authentication_authorization_example.security.token.CustomAuthenticationToken;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import java.security.Key;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;


@Component
@ConfigurationProperties(prefix = "jwt")
public class JWTUtil {

    private String secret;
    private int expirationInMinute;

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public void setExpirationInMinute(int expirationInMinute) {
        this.expirationInMinute = expirationInMinute;
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public List<GrantedAuthority> extractRoles(String token) {
        final Claims claims = extractAllClaims(token);
        return Arrays.stream(claims.get("role").toString().split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    public ResponseCookie generateJwtCookie(CustomAuthenticationToken customAuthenticationToken) {
        String jwt = generateJwtToken(customAuthenticationToken);
        return ResponseCookie.from(Constant.COOKIE_NAME, jwt)
                .path("/")
                .domain("localhost")
                .httpOnly(true)
                .secure(false)
                .sameSite(org.springframework.boot.web.server.Cookie.SameSite.LAX.toString())
                .build();
    }

    public Cookie generateCookieForClearingFromBrowser() {
        Cookie cookie = new Cookie(Constant.COOKIE_NAME, "");
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setSecure(false);
        cookie.setMaxAge(0);
        cookie.setAttribute("sameSite", "Lax");
        return cookie;
    }

    public String generateJwtToken(CustomAuthenticationToken customAuthenticationToken) {

        var issuedAt = new Date();
        var expire = new Date(issuedAt.getTime() + ((long) expirationInMinute * 60 * 1000));
        return Jwts.builder()
                .setIssuedAt(issuedAt)
                .setExpiration(expire)
                .setSubject((String) customAuthenticationToken.getPrincipal())
                .addClaims(Collections.singletonMap("role",
                        customAuthenticationToken.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(","))))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String getJwtFromCookies(HttpServletRequest request, String cookieName) {
        Cookie cookie = WebUtils.getCookie(request, cookieName);
        return cookie != null ? cookie.getValue() : null;
    }

    public boolean isTokenValid(String token) {
        return !isTokenExpired(token);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
