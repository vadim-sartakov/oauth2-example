package com.example.cloud.gateway.filter;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetailsSource;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.WebUtils;

public class OAuth2AuthenticationFilter extends BasicAuthenticationFilter {
   
    @Autowired private ResourceServerTokenServices tokenServices;
    private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new OAuth2AuthenticationDetailsSource();
    
    @Autowired
    @LoadBalanced
    private RestTemplate restTemplate;
    
    public OAuth2AuthenticationFilter(AuthenticationManager authenticationManager) {
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
                OAuth2AccessToken accessToken = restTemplate.postForObject(
                        "http://auth-server/auth/oauth/token?grant_type=refresh_token&refresh_token={refresh_token}",
                        null,
                        OAuth2AccessToken.class,
                        WebUtils.getCookie(request, "refresh-token").getValue());
                authentication = tokenServices.loadAuthentication(accessToken.getValue());
            }
            request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE, cookie.getValue());
            request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_TYPE, "bearer");
            authentication.setDetails(authenticationDetailsSource.buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);
            
        }
        
        chain.doFilter(request, response);
        
    }
    
    private void addCookie() {
        
    }
    
}
