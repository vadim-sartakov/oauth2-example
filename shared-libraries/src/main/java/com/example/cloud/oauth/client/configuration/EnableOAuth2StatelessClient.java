package com.example.cloud.oauth.client.configuration;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.context.annotation.Import;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Import(OAuth2StatelessClientConfiguration.class)
public @interface EnableOAuth2StatelessClient {
    
}
