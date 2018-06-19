package com.example.cloud.authserver.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationListener implements ApplicationListener<AuthenticationSuccessEvent> {

    @Autowired private HttpServletRequest request;
    @Autowired private HttpServletResponse response;
    @Autowired private JwtAccessTokenConverter jwtTokenConverter;
    @Autowired private ObjectMapper objectMapper;
    
    @SuppressWarnings("unchecked")
    @Override
    public void onApplicationEvent(AuthenticationSuccessEvent event) {
        
        String content;
        try {
            content = objectMapper.writeValueAsString(event.getAuthentication().getPrincipal());
        } catch (JsonProcessingException e) {
            throw new RuntimeException();
        }
        
        String jwt = JwtHelper.encode(content, new MacSigner("test")).getEncoded();
        
        Cookie cookie = new Cookie("token", jwt);
        cookie.setSecure(request.isSecure());
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        response.addCookie(cookie);
        
    }
    
}
