package com.example.cloud.gateway.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;

@Configuration
public class RestTemplateConfig {
    
    @Autowired private OAuth2ProtectedResourceDetails resourceDetails;
    @Autowired private OAuth2ClientContext clientContext;
    
    @Bean
    @LoadBalanced
    public OAuth2RestTemplate systemRestTemplate() {
        return new OAuth2RestTemplate(resourceDetails, clientContext);
    }
    
}
