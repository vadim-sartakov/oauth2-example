package com.example.cloud.gateway.config;

import com.example.cloud.gateway.filter.OAuth2CookieToHeaderAuthenticationFilter;
import com.example.cloud.gateway.filter.OAuth2RefreshTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
@EnableResourceServer
@EnableOAuth2Client
public class SecurityConfig extends ResourceServerConfigurerAdapter {
           
    @Autowired private OAuth2ClientContext oAuth2ClientContext;
    @Autowired private DefaultTokenServices tokenServices;
    @Autowired private AuthorizationCodeResourceDetails resourceDetails;
    
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                    .antMatchers("/login**", "/auth/**")
                    .permitAll()
                    .anyRequest()
                    .authenticated()
                .and()
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                    .addFilterBefore(refreshTokenFilter(), AbstractPreAuthenticatedProcessingFilter.class)
                    .addFilterBefore(authServerClient(), AbstractPreAuthenticatedProcessingFilter.class)
                    .addFilterBefore(cookieToHeaderAuthentication(), AbstractPreAuthenticatedProcessingFilter.class)
                .csrf()
                    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                    .ignoringAntMatchers("/auth/oauth/token");
    }
    
    @Bean
    public OAuth2RefreshTokenFilter refreshTokenFilter() {
        return new OAuth2RefreshTokenFilter();
    }
    
    @Bean
    public OAuth2CookieToHeaderAuthenticationFilter cookieToHeaderAuthentication() {
        return new OAuth2CookieToHeaderAuthenticationFilter();
    }
        
    @Bean
    public OAuth2ClientAuthenticationProcessingFilter authServerClient() {
        OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter("/login");
        OAuth2RestTemplate restTemplate = new OAuth2RestTemplate(resourceDetails, oAuth2ClientContext);
        tokenServices.setSupportRefreshToken(true);
        filter.setTokenServices(tokenServices);
        filter.setRestTemplate(restTemplate);
        return filter;
    }
        
}
