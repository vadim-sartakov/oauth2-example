package com.example.cloud.oauth.client.filter;

import java.io.IOException;
import java.util.Arrays;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.util.WebUtils;

public class OAuth2RefreshTokenFilter extends GenericFilterBean {
    
    @Autowired private AuthorizationCodeResourceDetails resourceDetails;
    @Autowired private OAuth2ClientContext clientContext;
    @Autowired private TokenStore tokenStore;
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        
        try {
            chain.doFilter(request, response);
        } catch(BadCredentialsException bad) {
            
            Throwable cause = bad.getCause();
            if (cause instanceof OAuth2Exception && cause.getMessage().contains("expired")) {
                    
                if (logger.isDebugEnabled()) {
                    logger.debug("Refreshing access token");
                }
                
                Cookie cookie = WebUtils.getCookie(httpRequest, OAuth2AccessToken.REFRESH_TOKEN);
                if (cookie != null) {

                    AuthorizationCodeAccessTokenProvider provider = new AuthorizationCodeAccessTokenProvider();
                    AccessTokenRequest tokenRequest = new DefaultAccessTokenRequest();
                    
                    OAuth2AccessToken accessToken = null;
                    try {
                        accessToken = provider.refreshAccessToken(resourceDetails, tokenStore.readRefreshToken(cookie.getValue()), tokenRequest);
                    } catch(OAuth2AccessDeniedException | UserRedirectRequiredException e) {
                        if (logger.isDebugEnabled()) {
                            logger.debug("Unable to refresh token");
                        }
                    }
                    clientContext.setAccessToken(accessToken);
                    httpRequest = new RefreshTokenRequestWrapper(httpRequest, accessToken);

                    if (logger.isDebugEnabled()) {
                        logger.debug("Forwarding request to " + httpRequest.getRequestURI());
                    }
                    
                    httpRequest.getRequestDispatcher(httpRequest.getRequestURI()).forward(httpRequest, response);

                }
            }
        }
    }
    
    public static class RefreshTokenRequestWrapper extends HttpServletRequestWrapper {
        
        private final OAuth2AccessToken accessToken;

        public RefreshTokenRequestWrapper(HttpServletRequest request, OAuth2AccessToken accessToken) {
            super(request);
            this.accessToken = accessToken;
        }
        
        @Override
        public Cookie[] getCookies() {
            Cookie[] cookies = super.getCookies();
            if (accessToken == null) {
                cookies = Arrays.stream(cookies)
                        .filter(cookie -> !(cookie.getName().equals(OAuth2AccessToken.ACCESS_TOKEN) || cookie.getName().equals(OAuth2AccessToken.REFRESH_TOKEN)))
                        .toArray(Cookie[]::new);
            } else {
                Arrays.stream(cookies)
                        .filter(cookie -> cookie.getName().equals(OAuth2AccessToken.ACCESS_TOKEN))
                        .findFirst()
                        .ifPresent(cookie -> cookie.setValue(accessToken.getValue()));
            }
            return cookies;
        }

    }
    
}
