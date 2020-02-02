package com.auth.security.filter;

import com.core.model.ApplicationUser;
import com.core.property.JwtConfiguration;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import com.token.security.token.creator.TokenCreator;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Objects;

import static java.util.Collections.emptyList;

@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@Slf4j
public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final JwtConfiguration jwtConfiguration;
    private final TokenCreator tokenCreator;

    @Override
    @SneakyThrows
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        log.info("Attempting authentication. . .");

        ApplicationUser user = new ObjectMapper().readValue(request.getInputStream(), ApplicationUser.class);

        if(Objects.isNull(user))
            throw new UsernameNotFoundException("Uneble to retrive username or password");

        log.info("Creating the authentication object for de user '{}' and calling UserDetailsServiceImpl loadUserByUsername", user.getUsername());

        UsernamePasswordAuthenticationToken token =
                new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword(), emptyList());

        token.setDetails(user);

        return authenticationManager.authenticate(token);
    }

    @Override
    @SneakyThrows
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult){
        log.info("Authentication was succesfull for the user '{}'", authResult.getName());
        SignedJWT signedJwt = tokenCreator.createSignedJwt(authResult);
        String token = tokenCreator.encryptToken(signedJwt);
        log.info("Token generated succesfully");

        response.addHeader("Acess-Control-Expose-Headers", "XSRF-TOKEN," + jwtConfiguration.getHeader().getName());
        response.addHeader(jwtConfiguration.getHeader().getName(), jwtConfiguration.getHeader().getPrefix() + token);

    }

}
