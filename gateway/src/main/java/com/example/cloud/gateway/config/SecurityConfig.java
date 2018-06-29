package com.example.cloud.gateway.config;

import com.example.cloud.shared.oauth.client.configuration.EnableOAuth2StatelessClient;
import com.example.cloud.shared.oauth.client.OAuth2StatelessClientAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerTokenServicesConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;

@Configuration
@EnableWebSecurity
@EnableOAuth2StatelessClient
@Import(ResourceServerTokenServicesConfiguration.class)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    
    @Autowired private ResourceServerTokenServices tokenServices;
    @Autowired private OAuth2RestTemplate restTemplate;
    @Autowired private OAuth2ClientContext clientContext;
    
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .requestMatcher(new NegatedRequestMatcher(new AntPathRequestMatcher("/auth/**")))
                .authorizeRequests()
                    .anyRequest()
                    .permitAll()
                .and()
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .csrf()
                    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .and()
                    .addFilterBefore(clientAuthenticationFilter(), AbstractPreAuthenticatedProcessingFilter.class)
                    .addFilterBefore(authenticationFilter(), AbstractPreAuthenticatedProcessingFilter.class);
    }
 
    private OAuth2ClientAuthenticationProcessingFilter clientAuthenticationFilter() {
        OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter("/login");
        filter.setTokenServices(tokenServices);
        filter.setRestTemplate(restTemplate);
        return filter;
    }
    
    private OAuth2StatelessClientAuthenticationFilter authenticationFilter() {
        return new OAuth2StatelessClientAuthenticationFilter(tokenServices, restTemplate, clientContext);
    }
    
}
