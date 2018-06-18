package com.example.cloud.gateway.config;

import com.example.cloud.gateway.filter.JWTAuthorizationFilter;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

@Configuration
@EnableOAuth2Sso
public class SecurityConfig extends WebSecurityConfigurerAdapter {
           
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                    .antMatchers("/auth/**")
                    .permitAll()
                    .anyRequest()
                    .authenticated()
                /*.and()
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)*/
                .and()
                    .formLogin()
                .and()
                    .csrf().disable()
                    .addFilter(jwtAuthorizationFilter());
    }

    @Bean
    public JWTAuthorizationFilter jwtAuthorizationFilter() throws Exception {
        return new JWTAuthorizationFilter(authenticationManager());
    }
    
}
