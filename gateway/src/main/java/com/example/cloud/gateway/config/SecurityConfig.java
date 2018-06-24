package com.example.cloud.gateway.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerTokenServicesConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableResourceServer
@EnableOAuth2Client
@Import(ResourceServerTokenServicesConfiguration.class)
public class SecurityConfig extends ResourceServerConfigurerAdapter {
           
    @Autowired private OAuth2ClientContext oAuth2ClientContext;
    @Autowired private ResourceServerTokenServices tokenServices;
    @Autowired private AuthorizationCodeResourceDetails resourceDetails;
    
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                    .antMatchers("/auth/**")
                    .permitAll()
                    .anyRequest()
                    .authenticated()
                .and()
                    .addFilterBefore(authServerClient(), BasicAuthenticationFilter.class);
    }
            
    @Bean
    public OAuth2ClientAuthenticationProcessingFilter authServerClient() {
        OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter("/login");
        OAuth2RestTemplate restTemplate = new OAuth2RestTemplate(resourceDetails, oAuth2ClientContext);
        filter.setTokenServices(tokenServices);
        filter.setRestTemplate(restTemplate);
        return filter;
    }
        
}
