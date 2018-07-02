package com.example.cloud.authserver.config;

import com.example.cloud.shared.oauth.client.OAuth2StatelessClientAuthenticationFilter;
import com.example.cloud.shared.oauth.client.configuration.EnableOAuth2StatelessClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;

@Configuration
@EnableWebSecurity
@EnableOAuth2StatelessClient
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired private OAuth2ClientAuthenticationProcessingFilter authServerClientAuthenticationFilter;
    @Autowired private OAuth2ClientAuthenticationProcessingFilter githubClientAuthenticationFilter;

    @Autowired
    @Qualifier("authServerStatelessClientAuthenticationFilter")
    private OAuth2StatelessClientAuthenticationFilter authenticationFilter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                    .antMatchers("/login", "/index.html")
                        .permitAll()
                    .anyRequest()
                        .authenticated()
                .and()
                    .sessionManagement()
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                    .csrf()
                        .csrfTokenRepository(tokenRepository())
                        .ignoringAntMatchers("/oauth/token")
                .and()
                    .addFilterBefore(authServerClientAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                    .addFilterBefore(githubClientAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                    .addFilterBefore(authenticationFilter, AbstractPreAuthenticatedProcessingFilter.class);
    }

    private CsrfTokenRepository tokenRepository() {
        CookieCsrfTokenRepository tokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        tokenRepository.setCookieName("ACCOUNT-XSRF-TOKEN");
        return tokenRepository;
    }

}
