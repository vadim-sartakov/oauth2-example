package com.example.cloud.gateway.filter;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.web.filter.GenericFilterBean;

public class OAuth2RefreshTokenFilter extends GenericFilterBean {

    @Autowired private AuthorizationCodeResourceDetails resourceDetails;
    @Autowired private OAuth2ClientContext clientContext;
    
    private OAuth2RestTemplate restTemplate;
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        try {
            chain.doFilter(request, response);
        } catch(BadCredentialsException bad) {
            Throwable cause = bad.getCause();
            if (cause instanceof OAuth2Exception) {
                OAuth2Exception oauth2Cause = (OAuth2Exception) cause;
                if (oauth2Cause.getMessage().contains("expired")) {
                    restTemplate.getAccessToken();
                }
            }
            chain.doFilter(request, response);
        }
    }

    @Override
    public void afterPropertiesSet() throws ServletException {
        super.afterPropertiesSet();
        restTemplate = new OAuth2RestTemplate(resourceDetails, clientContext);
    }
    
}
