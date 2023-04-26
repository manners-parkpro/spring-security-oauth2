package com.spring.oauth2.configuration;

import lombok.extern.log4j.Log4j2;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

@Log4j2
public class CustomSecurityConfiguration extends AbstractHttpConfigurer<CustomSecurityConfiguration, HttpSecurity> {

    private boolean isSecure;

    @Override
    public void init(HttpSecurity builder) throws Exception {
        super.init(builder);
        log.info("CustomSecurityConfiguration Init Method Started ...");
    }

    @Override
    public void configure(HttpSecurity builder) throws Exception {
        super.configure(builder);
        log.info("CustomSecurityConfiguration Configure Method Started ...");

        if (isSecure)
            log.info("https is Required ...");
        else
            log.info("https is Optional ...");
    }

    public CustomSecurityConfiguration setSecure(boolean isSecure) {
        this.isSecure = isSecure;
        return this;
    }
}
