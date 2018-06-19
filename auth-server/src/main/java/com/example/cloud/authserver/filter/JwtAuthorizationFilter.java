package com.example.cloud.authserver.filter;

import java.io.IOException;
import java.security.Principal;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.util.WebUtils;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
    
    public JwtAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        
        Cookie cookie = WebUtils.getCookie(request, "token");
        /*if (cookie != null) {
            Principal authentication = JwtHelper.decode(cookie.getValue()).;
            request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE, cookie.getValue());
            request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_TYPE, "bearer");
            authentication.setDetails(authenticationDetailsSource.buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }*/
        
        chain.doFilter(request, response);
    }
    
}
