package com.example.cloud.gateway.config;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.stereotype.Component;

@Component
public class OAuth2ClientContextBeanFactoryPostProcessor implements BeanFactoryPostProcessor {

    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {    
        BeanDefinition beanDef = beanFactory.getBeanDefinition("scopedTarget.oauth2ClientContext");
        beanDef.setScope("request");
    }
    
}
