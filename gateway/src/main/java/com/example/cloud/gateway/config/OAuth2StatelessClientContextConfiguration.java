package com.example.cloud.gateway.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.ServletContext;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.web.util.WebUtils;

@Configuration
public class OAuth2StatelessClientContextConfiguration {
    
    @Bean
    @Scope(value = "request", proxyMode = ScopedProxyMode.INTERFACES)
    @Primary
    public DefaultOAuth2ClientContext oauth2StatelessClientContext(
            @Qualifier("accessTokenRequest") ObjectProvider<AccessTokenRequest> accessTokenRequest) {
        return new StatelessOAuth2ClientContext(accessTokenRequest.getIfAvailable());
    }

    public static class StatelessOAuth2ClientContext extends DefaultOAuth2ClientContext {
        
        public static final String STATE_COOKIE = "state";
        
        @Autowired private HttpServletRequest request;
        @Autowired private HttpServletResponse response;
        @Autowired private ServletContext servletContext;
        
        @Autowired private ObjectMapper objectMapper;
        @Autowired private TokenStore tokenStore;
        
        private OAuth2AccessToken currentAccessToken;

        public StatelessOAuth2ClientContext(AccessTokenRequest accessTokenRequest) {
            super(accessTokenRequest);
        }

        @Override
        public void setAccessToken(OAuth2AccessToken accessToken) {
            
            if (accessToken == null) {
                addCookie(OAuth2AccessToken.ACCESS_TOKEN, "", 0);
                addCookie(OAuth2AccessToken.REFRESH_TOKEN, "", 0);
                return;
            }
            
            addCookie(OAuth2AccessToken.ACCESS_TOKEN, accessToken.getValue(), -1);
            
            if (accessToken.getRefreshToken() != null)
                addCookie(OAuth2AccessToken.REFRESH_TOKEN, accessToken.getRefreshToken().getValue(), -1);
            
            currentAccessToken = accessToken;
            
        }

        @Override
        public OAuth2AccessToken getAccessToken() {
            
            if (currentAccessToken != null)
                return currentAccessToken;
            
            Cookie accessTokenCookie = WebUtils.getCookie(request, OAuth2AccessToken.ACCESS_TOKEN);
            Cookie refreshTokenCookie = WebUtils.getCookie(request, OAuth2AccessToken.REFRESH_TOKEN);
            
            if (accessTokenCookie == null)
                return null;
            
            OAuth2AccessToken accessToken = tokenStore.readAccessToken(accessTokenCookie.getValue());
            if (refreshTokenCookie != null && accessToken instanceof DefaultOAuth2AccessToken)
                ((DefaultOAuth2AccessToken) accessToken).setRefreshToken(tokenStore.readRefreshToken(refreshTokenCookie.getValue()));
            
            return accessToken;
            
        }
 
        @Override
        public void setPreservedState(String stateKey, Object preservedState) {
            String state;
            Map<String, String> stateMap = new HashMap<>();
            stateMap.put(stateKey, preservedState.toString());
            try {
                state = Base64.getEncoder().encodeToString(
                        objectMapper.writeValueAsString(stateMap).getBytes(StandardCharsets.UTF_8)
                );
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
            addCookie(STATE_COOKIE, state, -1);
        }

        @SuppressWarnings("unchecked")
        @Override
        public Object removePreservedState(String stateKey) {
            
            Cookie cookie = WebUtils.getCookie(request, STATE_COOKIE);
            if (cookie == null) return null;
            
            Map<String, String> stateMap;
            try {
                stateMap = (Map<String, String>) objectMapper.readValue(
                        new String(Base64.getDecoder().decode(cookie.getValue()), StandardCharsets.UTF_8),
                        HashMap.class);
            } catch(IOException e) {
                throw new RuntimeException(e);
            }
            
            Object value = stateMap.remove(stateKey);
            
            if (stateMap.isEmpty())
                addCookie(STATE_COOKIE, "", 0);
            else
                try {
                    addCookie(STATE_COOKIE, objectMapper.writeValueAsString(stateMap), -1);
                } catch(JsonProcessingException e) {
                    throw new RuntimeException(e);
                }
            
            return value;
            
        }
        
        private void addCookie(String name, String value, int maxAge) {
            Cookie cookie = new Cookie(name, value);
            cookie.setSecure(request.isSecure());
            cookie.setHttpOnly(true);
            cookie.setMaxAge(maxAge);
            cookie.setPath(servletContext.getContextPath().isEmpty() ? "/" : servletContext.getContextPath());
            response.addCookie(cookie);
        }

    }
    
}
