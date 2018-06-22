package com.example.cloud.authserver.config;

import com.example.cloud.authserver.filter.OAuth2UsernamePasswordAuthenticationFilter;
import com.example.cloud.shared.filter.OAuth2AuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
        
    @Autowired private JwtTokenStore tokenStore;
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                    .antMatchers("/login**", "/oauth/token")
                        .permitAll()
                    .anyRequest()
                        .authenticated()
                .and()
                    .sessionManagement()
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                /*.and()
                    .formLogin().loginPage("/login")*/
                .and()
                    .csrf().csrfTokenRepository(cookieCsrfTokenRepository()).ignoringAntMatchers("/oauth/token")
                .and()
                    .addFilterBefore(authenticationFilter(), BasicAuthenticationFilter.class)
                    .addFilterAfter(oAuth2UsernamePasswordAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }
        
    @Bean
    public ResourceServerTokenServices tokenServices() {
        DefaultTokenServices tokenServices = new DefaultTokenServices();
        tokenServices.setTokenStore(tokenStore);
        return tokenServices;
    }
    
    @Bean
    public OAuth2AuthenticationFilter authenticationFilter() {
        return new OAuth2AuthenticationFilter();
    }
    
    @Bean
    public OAuth2UsernamePasswordAuthenticationFilter oAuth2UsernamePasswordAuthenticationFilter() throws Exception {
        OAuth2UsernamePasswordAuthenticationFilter filter = new OAuth2UsernamePasswordAuthenticationFilter();
        filter.setAuthenticationManager(authenticationManager());
        return filter;
    }
        
    @Bean
    public CsrfTokenRepository cookieCsrfTokenRepository() {
        return CookieCsrfTokenRepository.withHttpOnlyFalse();
    }
    
}
