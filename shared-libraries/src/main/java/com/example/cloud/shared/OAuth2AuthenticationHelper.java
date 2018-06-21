package com.example.cloud.shared;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class OAuth2AuthenticationHelper {
    
    public static final String ACCESS_TOKEN_COOKIE = "access-token";
    public static final String REFRESH_TOKEN_COOKIE = "refresh-token";
    
    public void addCookie(HttpServletRequest request, HttpServletResponse response, ServletContext servletContext) {
        
    }
    
}
