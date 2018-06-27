package com.example.cloud.oauth.client;

import java.lang.reflect.Field;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.util.ReflectionUtils;

public class OAuth2RefreshableRestTemplate extends OAuth2RestTemplate {
    
    private final OAuth2ProtectedResourceDetails resource;
    private final OAuth2ClientContext context;
    private final AccessTokenProvider accessTokenProvider;

    @SuppressWarnings("unchecked")
    public OAuth2RefreshableRestTemplate(OAuth2ProtectedResourceDetails resource, OAuth2ClientContext context) {
        super(resource, context);
        this.resource = resource;
        this.context = context;
        Field field = ReflectionUtils.findField(OAuth2RestTemplate.class, "accessTokenProvider");
        ReflectionUtils.makeAccessible(field);
        this.accessTokenProvider = (AccessTokenProvider) ReflectionUtils.getField(field, this);
    }

    @Override
    protected OAuth2AccessToken acquireAccessToken(OAuth2ClientContext oauth2Context) throws UserRedirectRequiredException {
        refreshAccessToken();
        return super.acquireAccessToken(oauth2Context);
    }
    
    public OAuth2AccessToken refreshAccessToken() {
        OAuth2AccessToken accessToken = context.getAccessToken();
        if (accessToken != null && accessToken.isExpired()) {
            accessToken = accessTokenProvider.refreshAccessToken(
                    resource, accessToken.getRefreshToken(),
                    context.getAccessTokenRequest()
            );
            context.setAccessToken(accessToken);
        }
        return accessToken;
    }
    
}
