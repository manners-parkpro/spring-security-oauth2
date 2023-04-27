package com.spring.oauth2.configuration;

import com.spring.oauth2.filter.CustomOAuth2AuthenticationFilter;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Log4j2
@RequiredArgsConstructor
@EnableWebSecurity
public class OAuth2Configuration {

    private final DefaultOAuth2AuthorizedClientManager authorizedClientManager;
    private final OAuth2AuthorizedClientRepository authorizedClientRepository;

    @Bean
    WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().antMatchers("/js/**", "/css/**", "/images/**", "/favicon.ico");
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.authorizeRequests(authRequest -> authRequest
                .antMatchers("/", "/oauth2Login", "/client").permitAll()
                .anyRequest().authenticated())
                .oauth2Client(Customizer.withDefaults());

        httpSecurity.addFilterBefore(customOAuth2AuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        return httpSecurity.build();
    }

    CustomOAuth2AuthenticationFilter customOAuth2AuthenticationFilter() throws Exception {
        CustomOAuth2AuthenticationFilter customOAuth2LoginAuthenticationFilter = new CustomOAuth2AuthenticationFilter(authorizedClientManager, authorizedClientRepository);
        customOAuth2LoginAuthenticationFilter.setAuthenticationSuccessHandler((request, response, authentication) -> {
            response.sendRedirect("/home");
        });

        return customOAuth2LoginAuthenticationFilter;
    }
}
