package com.example.cloud.authserver.config.client;

import com.example.cloud.shared.oauth.client.OAuth2StatelessClientContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

@Configuration
public class GithubClientConfiguration {
 
    @Autowired
    @Qualifier("accessTokenRequest")
    private AccessTokenRequest accessTokenRequest;
    
    @Bean
    @Scope(value = "request", proxyMode = ScopedProxyMode.INTERFACES)
    public OAuth2ClientContext githubClientContext() {
        return new OAuth2StatelessClientContext(accessTokenRequest, "github");
    }
    
    @Bean
    @ConfigurationProperties("github.client")
    public AuthorizationCodeResourceDetails githubResourceDetails() {
        return new AuthorizationCodeResourceDetails();
    }
    
    @Bean
    @ConfigurationProperties("github.resource")
    public ResourceServerProperties githubResourceServerProperties() {
        return new ResourceServerProperties();
    }
    
    @Bean
    public OAuth2RestTemplate githubRestTemplate() {
        return new OAuth2RestTemplate(githubResourceDetails(), githubClientContext());
    }
    
    @Bean
    public ResourceServerTokenServices githubTokenServices() {
        ResourceServerProperties resourceServerProperties = githubResourceServerProperties();
        UserInfoTokenServices tokenServices = new UserInfoTokenServices(resourceServerProperties.getUserInfoUri(), resourceServerProperties.getClientId());
        tokenServices.setRestTemplate(githubRestTemplate());
        return tokenServices;
    }
    
    @Bean
    public OAuth2ClientAuthenticationProcessingFilter githubClientAuthenticationFilter() {
        OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter("/login/github");
        filter.setRestTemplate(githubRestTemplate());
        filter.setTokenServices(githubTokenServices());
        return filter;
    }
    
}
