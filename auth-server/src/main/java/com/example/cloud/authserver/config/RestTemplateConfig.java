package com.example.cloud.authserver.config;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;

@Configuration
public class RestTemplateConfig {
    
    @Autowired private ResourceOwnerPasswordResourceDetails resourceDetails;
    @Autowired private OAuth2ClientContext clientContext;
    
    @Bean
    @LoadBalanced
    public OAuth2RestTemplate systemRestTemplate() {
        return new OAuth2RestTemplate(resourceDetails, clientContext);
    }
    
    @Configuration
    public static class ResourceDetailsConfig {

        @Bean
        @Scope(value = "request", proxyMode = ScopedProxyMode.TARGET_CLASS)
        public ResourceOwnerPasswordResourceDetails resourceOwnerPasswordDetails(HttpServletRequest request, HttpServletResponse response, AuthorizationCodeResourceDetails properties) {
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
