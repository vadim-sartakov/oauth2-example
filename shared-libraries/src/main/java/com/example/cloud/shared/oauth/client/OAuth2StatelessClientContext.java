/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.example.cloud.shared.oauth.client;

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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.web.util.WebUtils;

public class OAuth2StatelessClientContext extends DefaultOAuth2ClientContext {

    private final String stateCookieName;
    private final String accessTokenCookieName;
    private final String refreshTokenCookieName;
    
    @Autowired private HttpServletRequest request;
    @Autowired private HttpServletResponse response;
    @Autowired private ServletContext servletContext;

    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private TokenStore tokenStore;

    private OAuth2AccessToken currentAccessToken;

    public OAuth2StatelessClientContext(AccessTokenRequest accessTokenRequest) {
        this(accessTokenRequest, "");
    }
    
    public OAuth2StatelessClientContext(AccessTokenRequest accessTokenRequest, String prefix) {
        super(accessTokenRequest);
        this.stateCookieName = prefix + "_" + "state";
        this.accessTokenCookieName = prefix + "_" + OAuth2AccessToken.ACCESS_TOKEN;
        this.refreshTokenCookieName = prefix + "_" + OAuth2AccessToken.REFRESH_TOKEN;
    }

    @Override
    public void setAccessToken(OAuth2AccessToken accessToken) {

        if (accessToken == null) {
            addCookie(accessTokenCookieName, "", 0);
            addCookie(refreshTokenCookieName, "", 0);
            return;
        }

        addCookie(accessTokenCookieName, accessToken.getValue(), -1);

        if (accessToken.getRefreshToken() != null) {
            addCookie(refreshTokenCookieName, accessToken.getRefreshToken().getValue(), -1);
        }

        currentAccessToken = accessToken;

    }

    @Override
    public OAuth2AccessToken getAccessToken() {

        if (currentAccessToken != null) {
            return currentAccessToken;
        }

        Cookie accessTokenCookie = WebUtils.getCookie(request, accessTokenCookieName);
        Cookie refreshTokenCookie = WebUtils.getCookie(request, refreshTokenCookieName);

        if (accessTokenCookie == null) {
            return null;
        }

        OAuth2AccessToken accessToken = tokenStore.readAccessToken(accessTokenCookie.getValue());
        if (refreshTokenCookie != null && accessToken instanceof DefaultOAuth2AccessToken) {
            ((DefaultOAuth2AccessToken) accessToken).setRefreshToken(tokenStore.readRefreshToken(refreshTokenCookie.getValue()));
        }

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
        addCookie(stateCookieName, state, -1);
    }

    @SuppressWarnings("unchecked")
    @Override
    public Object removePreservedState(String stateKey) {

        Cookie cookie = WebUtils.getCookie(request, stateCookieName);
        if (cookie == null) {
            return null;
        }

        Map<String, String> stateMap;
        try {
            stateMap = (Map<String, String>) objectMapper.readValue(
                    new String(Base64.getDecoder().decode(cookie.getValue()), StandardCharsets.UTF_8),
                    HashMap.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        Object value = stateMap.remove(stateKey);

        if (stateMap.isEmpty()) {
            addCookie(stateCookieName, "", 0);
        } else {
            try {
                addCookie(stateCookieName, objectMapper.writeValueAsString(stateMap), -1);
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        }

        return value;

    }

    private void addCookie(String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setSecure(request.isSecure());
        cookie.setHttpOnly(true);
        cookie.setMaxAge(maxAge);
        cookie.setPath(getContextPath());
        response.addCookie(cookie);
    }
    
    private String getContextPath() {
        return servletContext.getContextPath().isEmpty() ? "/" : servletContext.getContextPath();
    }

}
