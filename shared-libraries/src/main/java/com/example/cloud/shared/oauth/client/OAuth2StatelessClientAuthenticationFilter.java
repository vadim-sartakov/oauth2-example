package com.example.cloud.shared.oauth.client;

import java.io.IOException;
import java.util.Collections;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetailsSource;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

public class OAuth2StatelessClientAuthenticationFilter extends OncePerRequestFilter {

    private final ResourceServerTokenServices tokenServices;
    private final OAuth2RestTemplate restTemplate;
    private final OAuth2ClientContext clientContext;
    private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new OAuth2AuthenticationDetailsSource();
    
    public OAuth2StatelessClientAuthenticationFilter(ResourceServerTokenServices tokenServices, OAuth2RestTemplate restTemplate, OAuth2ClientContext clientContext) {
        this.tokenServices = tokenServices;
        this.restTemplate = restTemplate;
        this.clientContext = clientContext;
    }  

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return SecurityContextHolder.getContext().getAuthentication() != null ||
                clientContext.getAccessToken() == null;
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        
        // Context needs to be populated with authentication to fire refresh token flow
        SecurityContextHolder.getContext().setAuthentication(new PreAuthenticatedAuthenticationToken("refresh-auth", null, Collections.emptyList()));
        OAuth2AccessToken accessToken = null;
        
        try {
            accessToken = restTemplate.getAccessToken();
        } catch (Exception e) {
            if (logger.isDebugEnabled())
                logger.debug("Failed to refresh token");                
        }
        AbstractAuthenticationToken authentication;
        if (accessToken != null) {
            authentication = tokenServices.loadAuthentication(accessToken.getValue());
            request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE, accessToken.getValue());
            request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_TYPE, accessToken.getTokenType());
            authentication.setDetails(authenticationDetailsSource.buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);
            if (logger.isDebugEnabled())
                logger.debug("Successfully authenticated " + authentication.toString());
        }
        
        if (accessToken == null)
            SecurityContextHolder.clearContext();
        
        chain.doFilter(request, response);

    }

}
