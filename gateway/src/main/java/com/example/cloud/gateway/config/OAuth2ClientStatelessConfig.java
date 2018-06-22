package com.example.cloud.gateway.config;

import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;

@Configuration
public class OAuth2ClientStatelessConfig {
    
    @Bean
    public OAuth2ClientContext oAuth2ClientContext() {
        AccessTokenRequest accessTokenRequest = new DefaultAccessTokenRequest();
        accessTokenRequest.setCurrentUri("http://localhost:8080/login");
        return new DefaultOAuth2ClientContext(accessTokenRequest);
    }
    
    @Bean
    public OAuth2ClientContextFilter clientContextFilter() {
        return new OAuth2ClientContextFilter();
    }
    
    @Bean
    public FilterRegistrationBean oauth2ClientFilterRegistration(
            OAuth2ClientContextFilter filter, SecurityProperties security) {
        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setFilter(filter);
        registration.setOrder(security.getFilterOrder() - 10);
        return registration;
    }

}
