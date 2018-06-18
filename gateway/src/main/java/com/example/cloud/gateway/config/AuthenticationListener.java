package com.example.cloud.gateway.config;

import javax.servlet.ServletContext;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoRestTemplateFactory;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationListener implements ApplicationListener<AuthenticationSuccessEvent> {

    public static String ACCESS_TOKEN_NAME = "access-token";
    public static String REFRESH_TOKEN_NAME = "refresh-token";
    
    @Autowired private HttpServletRequest request;
    @Autowired private HttpServletResponse response;
    @Autowired private ServletContext servletContext;
    
    @Autowired private UserInfoRestTemplateFactory restTemplateFactory;
    
    @Override
    public void onApplicationEvent(AuthenticationSuccessEvent event) {  
        OAuth2RestOperations restTemplate = restTemplateFactory.getUserInfoRestTemplate();
        OAuth2AccessToken token = restTemplate.getAccessToken();
        addCookie(ACCESS_TOKEN_NAME, token.getValue(), false, "/" + servletContext.getContextPath());
        addCookie(REFRESH_TOKEN_NAME, token.getRefreshToken().getValue(), true, "/" + servletContext.getContextPath());
    }
    
    private void addCookie(String name, String value, boolean httpOnly, String path) {
        Cookie cookie = new Cookie(name, value);
        cookie.setSecure(request.isSecure());
        cookie.setHttpOnly(httpOnly);
        cookie.setPath(path);
        response.addCookie(cookie);
    }
    
}
