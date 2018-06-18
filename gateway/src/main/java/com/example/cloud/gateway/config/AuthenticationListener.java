package com.example.cloud.gateway.config;

import javax.servlet.ServletContext;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationListener implements ApplicationListener<AuthenticationSuccessEvent> {

    @Autowired private HttpServletRequest request;
    @Autowired private HttpServletResponse response;
    @Autowired private ServletContext servletContext;
    
    @SuppressWarnings("unchecked")
    @Override
    public void onApplicationEvent(AuthenticationSuccessEvent event) {        
        OAuth2Authentication authentication = (OAuth2Authentication) event.getAuthentication();
        OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) authentication.getDetails();
        Cookie cookie = new Cookie("token", details.getTokenValue());
        cookie.setSecure(request.isSecure());
        cookie.setHttpOnly(true);
        cookie.setPath("/" + servletContext.getContextPath());
        response.addCookie(cookie);
    }
    
}
