package com.example.cloud.oauth.client.configuration;

import com.example.cloud.oauth.client.filter.OAuth2CookieToHeaderAuthenticationFilter;
import com.example.cloud.oauth.client.filter.OAuth2RefreshTokenFilter;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OAuth2StatelessClientSecurityConfiguration {
    
    @Bean
    public AuthenticationFailureListener authenticationFailureListener() {
        return new AuthenticationFailureListener();
    }
        
    @Bean
    public FilterRegistrationBean refreshTokenFilter(SecurityProperties properties) {
        FilterRegistrationBean filter = new FilterRegistrationBean(refreshTokenFilterBean());
        filter.setOrder(properties.getFilterOrder() - 2);
        return filter;
    }
    
    @Bean
    public OAuth2RefreshTokenFilter refreshTokenFilterBean() {
        return new OAuth2RefreshTokenFilter();
    }
        
    @Bean
    public FilterRegistrationBean cookieToHeaderAuthenticationFilter(SecurityProperties properties) {
        FilterRegistrationBean filter = new FilterRegistrationBean(new OAuth2CookieToHeaderAuthenticationFilter());
        filter.setOrder(properties.getFilterOrder() - 1);
        return filter;
    }

}
