package com.example.cloud.authserver.config;

import com.example.cloud.shared.oauth.client.configuration.EnableOAuth2StatelessClient;
import com.example.cloud.shared.oauth.client.OAuth2StatelessClientAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;

@Configuration
@EnableWebSecurity
@EnableOAuth2StatelessClient
public class SecurityConfig extends WebSecurityConfigurerAdapter {
            
    private final OAuth2ClientAuthenticationProcessingFilter authServerClientAuthenticationFilter;
    private final OAuth2ClientAuthenticationProcessingFilter githubClientAuthenticationFilter;
    private final OAuth2StatelessClientAuthenticationFilter authenticationFilter;

    @Autowired
    public SecurityConfig(OAuth2ClientAuthenticationProcessingFilter authServerClientAuthenticationFilter,
                          @Qualifier("githubClientAuthenticationFilter") OAuth2ClientAuthenticationProcessingFilter githubClientAuthenticationFilter,
                          OAuth2StatelessClientAuthenticationFilter authenticationFilter) {
        this.authServerClientAuthenticationFilter = authServerClientAuthenticationFilter;
        this.githubClientAuthenticationFilter = githubClientAuthenticationFilter;
        this.authenticationFilter = authenticationFilter;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                    .antMatchers("/login")
                        .permitAll()
                    .anyRequest()
                        .authenticated()
                .and()
                    .sessionManagement()
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                    .csrf()
                        .csrfTokenRepository(csrfTokenRepository())
                        .ignoringAntMatchers("/oauth/token")
                .and()
                    .addFilterBefore(authServerClientAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                    .addFilterBefore(githubClientAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                    .addFilterBefore(authenticationFilter, AbstractPreAuthenticatedProcessingFilter.class);
    }
    
    private CsrfTokenRepository csrfTokenRepository() {
        CookieCsrfTokenRepository tokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        tokenRepository.setCookieName("XSRF-TOKEN");
        return tokenRepository;
    }
        
}
