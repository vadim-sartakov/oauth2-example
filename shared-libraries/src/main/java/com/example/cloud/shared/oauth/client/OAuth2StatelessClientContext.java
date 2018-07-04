/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.example.cloud.shared.oauth.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.web.util.WebUtils;

import javax.servlet.ServletContext;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public class OAuth2StatelessClientContext implements OAuth2ClientContext {

    @Getter private final AccessTokenRequest accessTokenRequest;
    @Getter private final HttpServletRequest request;
    @Getter private final HttpServletResponse response;
    @Getter private final ObjectMapper objectMapper;
    @Getter private final TokenStore tokenStore;

    private final String contextPath;
    private final String stateCookieName;
    private final String accessTokenCookieName;
    private final String refreshTokenCookieName;

    private OAuth2AccessToken currentAccessToken;

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

        if (currentAccessToken != null) return currentAccessToken;

        Cookie accessTokenCookie = WebUtils.getCookie(request, accessTokenCookieName);
        Cookie refreshTokenCookie = WebUtils.getCookie(request, refreshTokenCookieName);

        if (accessTokenCookie == null) return null;

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
        addCookie(stateCookieName, state, -1);
    }

    @SuppressWarnings("unchecked")
    @Override
    public Object removePreservedState(String stateKey) {

        Cookie cookie = WebUtils.getCookie(request, stateCookieName);
        if (cookie == null) return null;

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
                addCookie(stateCookieName,
                        Base64.getEncoder().encodeToString(objectMapper.writeValueAsString(stateMap).getBytes(StandardCharsets.UTF_8)),
                        -1);
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
        cookie.setPath(contextPath);
        response.addCookie(cookie);
    }

    @Builder
    private static OAuth2StatelessClientContext newInstance(AccessTokenRequest accessTokenRequest,
                                                            HttpServletRequest request,
                                                            HttpServletResponse response,
                                                            ObjectMapper objectMapper,
                                                            TokenStore tokenStore,
                                                            String prefix,
                                                            ServletContext servletContext) {

        String contextPath = servletContext.getContextPath().isEmpty() ? "/" : servletContext.getContextPath();

        String resultPrefix = prefix == null ? "" : prefix.isEmpty() ? "" : prefix + "_";
        String stateCookieName = resultPrefix + "state";
        String accessTokenCookieName = resultPrefix + OAuth2AccessToken.ACCESS_TOKEN;
        String refreshTokenCookieName = resultPrefix + OAuth2AccessToken.REFRESH_TOKEN;

        OAuth2StatelessClientContext instance = new OAuth2StatelessClientContext(accessTokenRequest, request,
                response, objectMapper, tokenStore, contextPath, stateCookieName, accessTokenCookieName, refreshTokenCookieName);

        return instance;

    }

}
