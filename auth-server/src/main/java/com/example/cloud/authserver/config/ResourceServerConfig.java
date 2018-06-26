package com.example.cloud.authserver.config;

import com.example.cloud.oauth.client.configuration.EnableOAuth2StatelessClient;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.OAuth2ClientProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
@EnableResourceServer
@EnableOAuth2StatelessClient
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {
            
    @Autowired private OAuth2ClientAuthenticationProcessingFilter authenticationFilter;
    
    @Override
    public void configure(HttpSecurity http) throws Exception {
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
                    .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).ignoringAntMatchers("/oauth/token")
                .and()
                    .addFilterBefore(authenticationFilter, AbstractPreAuthenticatedProcessingFilter.class);
    }
    
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
    
    @Configuration
    public static class OAuth2ClientConfig {

        @Autowired private JwtTokenStore jwtTokenStore;
        @Autowired private OAuth2ClientContext oAuth2ClientContext;
        @Autowired private ResourceOwnerPasswordResourceDetails resourceOwnerPasswordDetails;

        @Bean
        @Primary
        public DefaultTokenServices jwtTokenServices() {
            DefaultTokenServices services = new DefaultTokenServices();
            services.setTokenStore(jwtTokenStore);
            return services;
        }
        
        @Bean
        public OAuth2ClientAuthenticationProcessingFilter authServerClientAuthenticationFilter() {
            OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter("/login");
            OAuth2RestTemplate restTemplate = new OAuth2RestTemplate(resourceOwnerPasswordDetails, oAuth2ClientContext);
            filter.setTokenServices(jwtTokenServices());
            filter.setRestTemplate(restTemplate);
            return filter;
        }

    }
    
}
