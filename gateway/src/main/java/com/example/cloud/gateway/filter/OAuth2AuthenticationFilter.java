package com.example.cloud.gateway.filter;

import javax.servlet.ServletContext;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.client.RestTemplate;

public class OAuth2AuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    
    @Autowired private HttpServletRequest request;
    @Autowired private HttpServletResponse response;
    @Autowired private ServletContext servletContext;
    
    @Autowired private RestTemplateBuilder restTemplateBuilder;
    @Autowired private ResourceServerTokenServices tokenServices;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        
        RestTemplate restTemplate = restTemplateBuilder
                .basicAuthorization("system", "secret")
                .build();
        
        ResponseEntity<DefaultOAuth2AccessToken> responseEntity = restTemplate.postForEntity(
                "http://localhost:8081/auth/oauth/token?grant_type=password&username={username}&password={password}",
                null,
                DefaultOAuth2AccessToken.class,
                obtainUsername(request),
                obtainPassword(request));
        
        OAuth2AccessToken token = responseEntity.getBody();
                
        addCookie("access-token", token.getValue());
        addCookie("refresh-token", token.getRefreshToken().getValue());
        
        OAuth2Authentication authentication = tokenServices.loadAuthentication(token.getValue());
        
        return authentication;
        
    }
    
    private void addCookie(String name, String value) {
        Cookie cookie = new Cookie(name, value);
        cookie.setSecure(request.isSecure());
        cookie.setHttpOnly(true);
        cookie.setPath(servletContext.getContextPath().isEmpty() ? "/" : servletContext.getContextPath());
        response.addCookie(cookie);
    }
    
}
