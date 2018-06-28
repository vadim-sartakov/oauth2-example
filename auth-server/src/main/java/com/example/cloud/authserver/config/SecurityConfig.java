package com.example.cloud.authserver.config;

import com.example.cloud.shared.oauth.client.configuration.EnableOAuth2StatelessClient;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;

@Configuration
@EnableWebSecurity
@EnableOAuth2StatelessClient
public class SecurityConfig extends WebSecurityConfigurerAdapter {
            
    @Autowired private ResourceServerTokenServices tokenServices;
    @Autowired private ResourceOwnerPasswordResourceDetails resourceDetails;
    @Autowired private OAuth2ClientContext clientContext;
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .requestMatcher(new NegatedRequestMatcher(new AntPathRequestMatcher("/oauth")))
                .authorizeRequests()
                    .antMatchers("/login")
                        .permitAll()
                    .anyRequest()
                        .authenticated()
                .and()
                    .sessionManagement()
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                    .csrf().disable()
                    .addFilterBefore(clientAuthenticationFilter(), AbstractPreAuthenticatedProcessingFilter.class);
    }
    
    @Bean
    public OAuth2RestTemplate authenticationRestTemplate() {
        return new OAuth2RestTemplate(resourceDetails, clientContext);
    }
    
    @Bean
    public OAuth2ClientAuthenticationProcessingFilter clientAuthenticationFilter() {
        OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter("/login") {
            // Narrowing authentication execution for POST requests only.
            // Since we use password grant type for self authentication.
            @Override
            protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
                return request.getMethod().equals("POST") && super.requiresAuthentication(request, response);
            }
        };
        filter.setTokenServices(tokenServices);
        filter.setRestTemplate(authenticationRestTemplate());
        return filter;
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
