package com.example.cloud.resourceserver.configuration;

import com.example.cloud.shared.oauth.client.configuration.EnableOAuth2StatelessClient;
import java.util.Collections;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

@Configuration
@EnableOAuth2StatelessClient
@EnableResourceServer
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

    @Autowired private OAuth2ProtectedResourceDetails resourceDetails;
    @Autowired private OAuth2ClientContext context;
    
    @Bean
    public OAuth2RestTemplate restTemplate() {
        return new OAuth2RestTemplate(resourceDetails, context);
    }
    
    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        super.configure(resources);
        OAuth2AuthenticationManager authenticationManager = new RefreshableAuthenticationManager(restTemplate());
        resources.authenticationManager(authenticationManager);
    }
    
    public static class RefreshableAuthenticationManager extends OAuth2AuthenticationManager {

        private final OAuth2RestTemplate restTemplate;

        public RefreshableAuthenticationManager(OAuth2RestTemplate restTemplate) {
            this.restTemplate = restTemplate;
        }
        
        @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            try {
                return super.authenticate(authentication);
            } catch (Exception e) {
                if (e.getMessage().contains("expired")) {
                    // Context needs to be populated with authentication to fire refresh token flow
                    SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("refresh-token", null, Collections.emptyList()));
                    OAuth2AccessToken token = restTemplate.getAccessToken();
                    Authentication refreshedAuthentication = new PreAuthenticatedAuthenticationToken(token.getValue(), "");
                    return super.authenticate(refreshedAuthentication);
                }
                throw e;
            }
        } 
        
    }
    
}
