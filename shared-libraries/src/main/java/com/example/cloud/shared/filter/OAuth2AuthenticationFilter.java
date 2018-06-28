package com.example.cloud.shared.filter;

import java.io.IOException;
import java.util.Collections;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetailsSource;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.web.filter.OncePerRequestFilter;

public class OAuth2AuthenticationFilter extends OncePerRequestFilter {

    private final ResourceServerTokenServices tokenServices;
    private final OAuth2RestTemplate restTemplate;
    private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new OAuth2AuthenticationDetailsSource();
    
    public OAuth2AuthenticationFilter(ResourceServerTokenServices tokenServices, OAuth2RestTemplate restTemplate) {
        this.tokenServices = tokenServices;
        this.restTemplate = restTemplate;
    }  
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            chain.doFilter(request, response);
            return;
        }
        
        // Context needs to be populated with authentication to fire refresh token flow
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("refresh-auth", null, Collections.emptyList()));
        OAuth2AccessToken accessToken = restTemplate.getAccessToken();
        AbstractAuthenticationToken authentication;
        if (accessToken != null) {
            authentication = tokenServices.loadAuthentication(accessToken.getValue());
            request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE, accessToken.getValue());
            request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_TYPE, accessToken.getTokenType());
            authentication.setDetails(authenticationDetailsSource.buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        
        chain.doFilter(request, response);

    }

}
