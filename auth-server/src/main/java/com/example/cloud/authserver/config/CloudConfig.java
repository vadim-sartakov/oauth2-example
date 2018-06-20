package com.example.cloud.authserver.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class CloudConfig {
    
    @Autowired private RestTemplateBuilder restTemplateBuilder;
    
    @Bean
    @LoadBalanced
    public RestTemplate loadBalancedRestTemplate() {
        return restTemplateBuilder.basicAuthorization("system", "secret").build();
    }
    
}
