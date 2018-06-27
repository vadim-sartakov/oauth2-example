package com.example.cloud.shared.filter;

import com.example.cloud.oauth.client.OAuth2RefreshableRestTemplate;
import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetailsSource;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

public class OAuth2AuthenticationFilter extends OncePerRequestFilter {

    private final AntPathRequestMatcher ignoreMatcher;
    private final ResourceServerTokenServices tokenServices;
    private final OAuth2RefreshableRestTemplate restTemplate;
    private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new OAuth2AuthenticationDetailsSource();
    
    public OAuth2AuthenticationFilter(ResourceServerTokenServices tokenServices, OAuth2RefreshableRestTemplate restTemplate) {
        this(null, tokenServices, restTemplate);
    }
    
    public OAuth2AuthenticationFilter(String ignoreAntPath, ResourceServerTokenServices tokenServices, OAuth2RefreshableRestTemplate restTemplate) {
        this.ignoreMatcher = ignoreAntPath == null ? null : new AntPathRequestMatcher(ignoreAntPath);
        this.tokenServices = tokenServices;
        this.restTemplate = restTemplate;
    }  
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            chain.doFilter(request, response);
            return;
        }
        
        OAuth2AccessToken accessToken = restTemplate.refreshAccessToken();
        if (accessToken != null) {
            OAuth2Authentication authentication = tokenServices.loadAuthentication(accessToken.getValue());
            request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE, accessToken.getValue());
            request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_TYPE, accessToken.getTokenType());
            authentication.setDetails(authenticationDetailsSource.buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        
        chain.doFilter(request, response);

    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return ignoreMatcher == null ? false : ignoreMatcher.matches(request);
    }

}
