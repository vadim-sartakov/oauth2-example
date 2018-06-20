package com.example.cloud.authserver.filter;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.ServletContext;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.web.HttpRequestMethodNotSupportedException;

public class OAuth2ServerAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    @Autowired private HttpServletRequest request;
    @Autowired private HttpServletResponse response;
    @Autowired private ServletContext servletContext;
     
    @Autowired private TokenEndpoint tokenEndpoint;
    @Autowired private ResourceServerTokenServices tokenServices;
    @Autowired private CsrfTokenRepository csrfTokenRepository;
    
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        
        Map<String, String> parameters = new HashMap<>();
        parameters.put("grant_type", "password");
        parameters.put("username", obtainUsername(request));
        parameters.put("password", obtainPassword(request));
        ResponseEntity<OAuth2AccessToken> responseEntity;
        UsernamePasswordAuthenticationToken clientAuthentication = new UsernamePasswordAuthenticationToken(
                "system",
                null,
                Arrays.asList(new SimpleGrantedAuthority("ROLE_SYSTEM")));
        try {
            responseEntity = tokenEndpoint.postAccessToken(clientAuthentication, parameters);
            // TODO: Analyze wrong credentials
        } catch (HttpRequestMethodNotSupportedException e) {
            throw new RuntimeException(e);
        }
        
        OAuth2AccessToken token = responseEntity.getBody();
                
        addCookie("access-token", token.getValue(), true);
        addCookie("refresh-token", token.getRefreshToken().getValue(), true);
        csrfTokenRepository.saveToken(null, request, response);
        CsrfToken csrfToken = csrfTokenRepository.generateToken(request);
        csrfTokenRepository.saveToken(csrfToken, request, response);
        
        OAuth2Authentication authentication = tokenServices.loadAuthentication(token.getValue());
        
        return authentication;
        
    }
    
    private void addCookie(String name, String value, boolean httpOnly) {
        Cookie cookie = new Cookie(name, value);
        cookie.setSecure(request.isSecure());
        cookie.setHttpOnly(httpOnly);
        cookie.setPath(servletContext.getContextPath().isEmpty() ? "/" : servletContext.getContextPath());
        response.addCookie(cookie);
    }

}
