package com.example.cloud.shared.oauth.client.configuration;

import com.example.cloud.shared.oauth.client.OAuth2StatelessClientContext;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;

@Configuration
@EnableOAuth2Client
public class OAuth2StatelessClientConfiguration {
    
    @Bean
    @Scope(value = "request", proxyMode = ScopedProxyMode.INTERFACES)
    @Primary
    public DefaultOAuth2ClientContext oauth2StatelessClientContext(
            @Qualifier("accessTokenRequest") ObjectProvider<AccessTokenRequest> accessTokenRequest) {
        return new OAuth2StatelessClientContext(accessTokenRequest.getIfAvailable());
    }
    
}
