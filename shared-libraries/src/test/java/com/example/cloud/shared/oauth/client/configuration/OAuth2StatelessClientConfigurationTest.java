package com.example.cloud.shared.oauth.client.configuration;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Ignore;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.stereotype.Controller;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;

public class OAuth2StatelessClientConfigurationTest {

    private WebApplicationContextRunner contextRunner = new WebApplicationContextRunner();

    @Test
    public void overridesSessionScopedClientContext() {
        contextRunner.withUserConfiguration(TestConfiguration.class, TestController.class)
                .run(context -> {
                    MockMvc mvc = MockMvcBuilders.webAppContextSetup(context).build();
                    mvc.perform(MockMvcRequestBuilders.get("/test"))
                            .andExpect(MockMvcResultMatchers.status().isOk());
                });
    }

    @Controller
    public static class TestController {

        @Autowired private OAuth2ClientContext clientContext;

        @GetMapping
        public String get() {
            clientContext.getAccessToken();
            return "";
        }

    }

    @Configuration
    @EnableOAuth2StatelessClient
    public static class TestConfiguration {

        @Bean
        public OAuth2RestTemplate restTemplate() {
            return Mockito.mock(OAuth2RestTemplate.class);
        }

        @Bean
        public ResourceServerTokenServices tokenServices() {
            return Mockito.mock(ResourceServerTokenServices.class);
        }

        @Bean
        public ObjectMapper objectMapper() {
            return Mockito.mock(ObjectMapper.class);
        }

        @Bean
        public TokenStore tokenStore() {
            return Mockito.mock(TokenStore.class);
        }

    }

}