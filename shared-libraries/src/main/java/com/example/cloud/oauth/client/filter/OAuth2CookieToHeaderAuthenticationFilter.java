package com.example.cloud.oauth.client.filter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.util.WebUtils;

public class OAuth2CookieToHeaderAuthenticationFilter extends GenericFilterBean {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletRequestWrapper requestWrapper = new CookieToHeaderAuthorizationRequestWrapper(httpRequest);        
        chain.doFilter(requestWrapper, response);
    }
    
    public static class CookieToHeaderAuthorizationRequestWrapper extends HttpServletRequestWrapper {
        
        public CookieToHeaderAuthorizationRequestWrapper(HttpServletRequest request) {
            super(request);
        }
        
        @Override
        public Enumeration<String> getHeaders(String name) {
            Enumeration<String> headers = super.getHeaders(name);
            if (!headers.hasMoreElements() && name.equals("Authorization")) {
                Cookie cookie = WebUtils.getCookie(this, OAuth2AccessToken.ACCESS_TOKEN);
                if (cookie != null) {
                    headers = Collections.enumeration(Arrays.asList("Bearer " + cookie.getValue()));
                }
            }
            return headers;
        }

    }
    
}
