package com.example.authentication_authorization_example.security;

import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@org.springframework.context.annotation.Configuration
public class Configuration {

    @Bean
    public UserDetailsService userDetailsService() {
        // InMemoryUserDetailsManager setup with two users
        UserDetails admin = User.withUsername("admin")
                .password(passwordEncoder().encode("password_admin"))
                //.password(Hashing.sha256().hashString("password_admin", StandardCharsets.UTF_8).toString())
                .roles("ADMIN", "USER")
                .build();
        System.out.println("kadir");
        System.out.println(passwordEncoder().encode("password_user"));
        UserDetails user = User.withUsername("user")
                .password(passwordEncoder().encode("password_user"))
                //.password(Hashing.sha256().hashString("user_admin", StandardCharsets.UTF_8).toString())
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(admin, user);
    }

    //$2a$10$o/0aXxLw9myi/iWDYBweV.tTKIgFG/1K48IpZtXev.nFumyoO2V6O
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(BCryptPasswordEncoder.BCryptVersion.$2A, 10);
    }
}
