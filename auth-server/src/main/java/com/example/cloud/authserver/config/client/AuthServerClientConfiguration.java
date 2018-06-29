package com.example.cloud.authserver.config.client;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;

@Configuration
public class AuthServerClientConfiguration {

    @Autowired
    @Qualifier("authServerResourceDetails")
    private ResourceOwnerPasswordResourceDetails resourceDetails;
    
    @Autowired private TokenStore tokenStore;
    @Autowired private OAuth2ClientContext clientContext;
    
    @Bean
    @Primary
    @LoadBalanced
    public OAuth2RestTemplate authServerRestTemplate() {
        return new OAuth2RestTemplate(resourceDetails, clientContext);
    }

    @Bean
    @Primary
    public ResourceServerTokenServices authServerTokenServices() {
        DefaultTokenServices services = new DefaultTokenServices();
        services.setTokenStore(tokenStore);
        return services;
    }
    
    @Bean
    public OAuth2ClientAuthenticationProcessingFilter authServerClientAuthenticationFilter() {
        OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter("/login");
        filter.setTokenServices(authServerTokenServices());
        filter.setRestTemplate(authServerRestTemplate());
        return filter;
    }
        
    @Configuration
    public static class ResourceDetailsConfig {

        @Bean
        @Scope(value = "request", proxyMode = ScopedProxyMode.TARGET_CLASS)
        public ResourceOwnerPasswordResourceDetails authServerResourceDetails(HttpServletRequest request, HttpServletResponse response, AuthorizationCodeResourceDetails properties) {
            ResourceOwnerPasswordResourceDetails resourceDetails = new ResourceOwnerPasswordResourceDetails();
            resourceDetails.setClientId(properties.getClientId());
            resourceDetails.setClientSecret(properties.getClientSecret());
            resourceDetails.setAccessTokenUri(properties.getAccessTokenUri());
            resourceDetails.setUsername(request.getParameter("username"));
            resourceDetails.setPassword(request.getParameter("password"));
            resourceDetails.setScope(properties.getScope());
            resourceDetails.setClientAuthenticationScheme(AuthenticationScheme.header);
            return resourceDetails;
        }

    }
    
}
