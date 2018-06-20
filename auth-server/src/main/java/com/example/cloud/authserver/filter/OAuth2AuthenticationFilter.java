package com.example.cloud.authserver.filter;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

public class OAuth2AuthenticationFilter extends OncePerRequestFilter {

    @Autowired private ResourceServerTokenServices tokenServices;
    
    @Autowired
    @LoadBalanced
    private RestTemplate restTemplate;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        Cookie cookie = WebUtils.getCookie(request, "access-token");
        if (cookie != null) {
            
            OAuth2Authentication authentication = null;
            try {
                authentication = tokenServices.loadAuthentication(cookie.getValue());
            } catch (InvalidTokenException e) {
                
                cookie = WebUtils.getCookie(request, "refresh-token");
                if (cookie != null) {
                                        
                    ResponseEntity<DefaultOAuth2AccessToken> responseEntity = restTemplate.postForEntity(
                        "http://auth-server/auth/oauth/token?grant_type=refresh_token&refresh_token={refresh_token}",
                        null,
                        DefaultOAuth2AccessToken.class,
                        cookie.getValue());
                    
                    // TODO: check for user credentials validity
                    OAuth2AccessToken token = responseEntity.getBody();
                    
                    // TODO: save cookie
                    authentication = tokenServices.loadAuthentication(token.getValue());
                    
                }                
                
            }
            
            SecurityContextHolder.getContext().setAuthentication(authentication);
                        
        }
        
        filterChain.doFilter(request, response);
        
    }
    
    private void addCookie() {
        
    }
    
}
