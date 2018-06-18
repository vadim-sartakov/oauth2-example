package com.example.cloud.gateway.filter;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoRestTemplateFactory;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetailsSource;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.util.WebUtils;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {
   
    private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new OAuth2AuthenticationDetailsSource();
    
    @Autowired private ResourceServerTokenServices tokenServices;
    @Autowired private UserInfoRestTemplateFactory restTemplateFactory;
    
    public JWTAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        
        Cookie cookie = WebUtils.getCookie(request, "access-token");
        if (cookie != null) {
            
            OAuth2Authentication authentication;
            try {
                authentication = tokenServices.loadAuthentication(cookie.getValue());
            } catch (AuthenticationException | InvalidTokenException e) {
                OAuth2RestOperations restTemplate = restTemplateFactory.getUserInfoRestTemplate();
                OAuth2AccessToken accessToken = restTemplate.getAccessToken();
                authentication = tokenServices.loadAuthentication(accessToken.getValue());
            }
            request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE, cookie.getValue());
            request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_TYPE, "bearer");
            authentication.setDetails(authenticationDetailsSource.buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);
            
        }
        
        chain.doFilter(request, response);
        
    }
    
}
