package com.example.cloud.gateway.config;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2RestOperationsConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;

@Configuration
public class OAuth2StatelessClientContextConfiguration {
    
    @Bean
    @Scope(value = "request", proxyMode = ScopedProxyMode.INTERFACES)
    @Primary
    @Qualifier("scopedTarget.oauth2ClientContext")
    public DefaultOAuth2ClientContext oauth2ClientContext(
            @Qualifier("accessTokenRequest") ObjectProvider<AccessTokenRequest> accessTokenRequest) {
        return new DefaultOAuth2ClientContext(accessTokenRequest.getIfAvailable());
    }

    /*public static class StatelessOAuth2ClientContext extends DefaultOAuth2ClientContext {
        
        @Autowired private HttpServletRequest request;
        @Autowired private HttpServletResponse response;
        @Autowired private ServletContext context;
        
        OAuth2RestOperationsConfiguration
        
    }*/
    
}
