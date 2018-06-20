package com.example.cloud.authserver.config;

import com.example.cloud.authserver.filter.OAuth2AuthenticationFilter;
import com.example.cloud.authserver.filter.OAuth2ServerAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
        
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
                .and()
                    .formLogin().loginPage("/login")
                .and()
                    .csrf().csrfTokenRepository(cookieCsrfTokenRepository()).ignoringAntMatchers("/oauth/token")
                .and()
                    .addFilterBefore(authorizatonFilter(), BasicAuthenticationFilter.class)
                    .addFilterBefore(authenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }
        
    @Bean
    public OAuth2ServerAuthenticationFilter authenticationFilter() throws Exception {
        OAuth2ServerAuthenticationFilter filter = new OAuth2ServerAuthenticationFilter();
        filter.setAuthenticationManager(authenticationManager());
        return filter;
    }
    
    @Bean
    public OAuth2AuthenticationFilter authorizatonFilter() {
        return new OAuth2AuthenticationFilter();
    }
    
    @Bean
    public CsrfTokenRepository cookieCsrfTokenRepository() {
        return CookieCsrfTokenRepository.withHttpOnlyFalse();
    }
    
}
