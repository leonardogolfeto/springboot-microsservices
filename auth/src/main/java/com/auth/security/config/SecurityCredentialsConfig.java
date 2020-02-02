package com.auth.security.config;

import com.auth.security.filter.JwtUsernameAndPasswordAuthenticationFilter;
import com.core.property.JwtConfiguration;
import com.token.security.filter.JwtTokenAuthorizationFilter;
import com.token.security.token.converter.TokenConverter;
import com.token.security.token.creator.TokenCreator;
import com.token.security.config.SecurityTokenConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
public class SecurityCredentialsConfig extends SecurityTokenConfig {
    private final TokenCreator tokenCreator;
    private final UserDetailsService userDetailsService;
    private final TokenConverter tokenConverter;

    @Autowired
    public SecurityCredentialsConfig(JwtConfiguration jwtConfiguration, UserDetailsService userDetailsService, TokenCreator tokenCreator, TokenConverter tokenConverter) {
        super(jwtConfiguration);
        this.userDetailsService = userDetailsService;
        this.tokenCreator = tokenCreator;
        this.tokenConverter = tokenConverter;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
             .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfiguration, tokenCreator))
             .addFilterAfter(new JwtTokenAuthorizationFilter(jwtConfiguration, tokenConverter), UsernamePasswordAuthenticationFilter.class);

        super.configure(http);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
