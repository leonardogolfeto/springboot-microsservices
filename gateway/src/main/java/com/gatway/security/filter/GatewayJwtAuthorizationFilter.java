package com.gatway.security.filter;

import com.core.property.JwtConfiguration;
import com.netflix.zuul.context.RequestContext;
import com.nimbusds.jwt.SignedJWT;
import com.token.security.filter.JwtTokenAuthorizationFilter;
import com.token.security.token.converter.TokenConverter;
import com.token.security.util.SecurityContextUtil;
import lombok.SneakyThrows;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class GatewayJwtAuthorizationFilter extends JwtTokenAuthorizationFilter {

    public GatewayJwtAuthorizationFilter(JwtConfiguration jwtConfiguration, TokenConverter tokenConverter) {
        super(jwtConfiguration, tokenConverter);
    }

    @SneakyThrows
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        String header = httpServletRequest.getHeader(jwtConfiguration.getHeader().getName());

        if (header == null || !header.startsWith(jwtConfiguration.getHeader().getPrefix())) {
            filterChain.doFilter(httpServletRequest, httpServletResponse);
            return;
        }
        String token = header.replace(jwtConfiguration.getHeader().getPrefix(), "").trim();

        String signedToken = tokenConverter.decryptToken(token);
        tokenConverter.validateTokenSignature(signedToken);

        SecurityContextUtil.setSecurityContext(SignedJWT.parse(signedToken));

        if(jwtConfiguration.getType().equalsIgnoreCase("signed"))
            RequestContext.getCurrentContext().addZuulRequestHeader("Authorization", jwtConfiguration.getHeader().getPrefix() + signedToken);

        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
}
