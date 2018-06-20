package com.example.cloud.authserver.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

public class JwtAuthorizationFilter extends OncePerRequestFilter {
    
    @Autowired private ObjectMapper objectMapper;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        
        Cookie cookie = WebUtils.getCookie(request, "token");
        if (cookie != null) {
           
            Jwt jwt = JwtHelper.decode(cookie.getValue());
            jwt.verifySignature(new MacSigner("test"));
            Map<String, String> claims = objectMapper.readValue(jwt.getClaims(), Map.class);
            // TODO: check if expires
            
            List<String> authorities = Arrays.asList(claims.get("authorities").split(","));
            List<GrantedAuthority> grantedAuthorities = authorities.stream()
                    .map(authority -> new SimpleGrantedAuthority(authority))
                    .collect(Collectors.toList());
            
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    claims.get("name"),
                    null,
                    grantedAuthorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            
        }
        
        chain.doFilter(request, response);
    }
    
}
