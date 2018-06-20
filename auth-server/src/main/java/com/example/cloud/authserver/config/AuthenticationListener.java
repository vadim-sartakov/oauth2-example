package com.example.cloud.authserver.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.servlet.ServletContext;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationListener implements ApplicationListener<AuthenticationSuccessEvent> {

    @Autowired private HttpServletRequest request;
    @Autowired private HttpServletResponse response;
    @Autowired private ServletContext servletContext;
    @Autowired private ObjectMapper objectMapper;
        
    @SuppressWarnings("unchecked")
    @Override
    public void onApplicationEvent(AuthenticationSuccessEvent event) {

        Authentication authentication = event.getAuthentication();        
        List<String> authorities = authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        
        Map<String, String> claims = new HashMap<>();
        claims.put("name", authentication.getName());
        claims.put("exp", authentication.getName());
        claims.put("authorities", StringUtils.join(authorities, ","));
                
        String content;
        try {
            content = objectMapper.writeValueAsString(claims);
        } catch(JsonProcessingException e) {
            throw new RuntimeException(e);
        }
        
        String jwt = JwtHelper.encode(content, new MacSigner("test")).getEncoded();
        
        Cookie cookie = new Cookie("token", jwt);
        cookie.setSecure(request.isSecure());
        cookie.setHttpOnly(true);
        cookie.setPath(servletContext.getContextPath().isEmpty() ? "/" : servletContext.getContextPath());
        response.addCookie(cookie);

    }
        
}
