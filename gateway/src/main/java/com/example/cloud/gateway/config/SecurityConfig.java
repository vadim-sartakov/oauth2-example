package com.example.cloud.gateway.config;

import com.example.cloud.oauth.client.OAuth2RefreshableRestTemplate;
import com.example.cloud.oauth.client.configuration.EnableOAuth2StatelessClient;
import com.example.cloud.shared.filter.OAuth2AuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerTokenServicesConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
@EnableWebSecurity
@EnableOAuth2StatelessClient
@Import(ResourceServerTokenServicesConfiguration.class)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
           
    @Autowired private OAuth2ClientContext oAuth2ClientContext;
    @Autowired private ResourceServerTokenServices tokenServices;
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
                    .addFilterBefore(clientAuthenticationFilter(), AbstractPreAuthenticatedProcessingFilter.class)
                    .addFilterBefore(authenticationFilter(), AbstractPreAuthenticatedProcessingFilter.class)
                .csrf()
                    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                    .ignoringAntMatchers("/auth/oauth/**");
    }
    
    @Bean
    public OAuth2RestTemplate authenticationRestTemplate() {
        return new OAuth2RefreshableRestTemplate(resourceDetails, oAuth2ClientContext);
    }
    
    @Bean
    public OAuth2ClientAuthenticationProcessingFilter clientAuthenticationFilter() {
        OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter("/login");
        filter.setTokenServices(tokenServices);
        filter.setRestTemplate(authenticationRestTemplate());
        return filter;
    }
    
    @Bean
    public OAuth2AuthenticationFilter authenticationFilter() {
        return new OAuth2AuthenticationFilter("/auth/**", tokenServices, authenticationRestTemplate());
    }
        
}
