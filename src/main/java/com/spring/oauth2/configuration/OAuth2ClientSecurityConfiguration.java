package com.spring.oauth2.configuration;

import com.spring.oauth2.entryPoint.Oauth2AuthenticationEntryPoint;
import com.spring.oauth2.resolver.CustomOAuth2AuthorizationRequestResolver;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Log4j2
@RequiredArgsConstructor
@EnableWebSecurity
public class OAuth2ClientSecurityConfiguration {

    private final Oauth2AuthenticationEntryPoint oauth2AuthenticationEntryPoint;
    private final ClientRegistrationRepository clientRegistrationRepository;

    /**
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        // oauth2Client -> 최종 사용자에 대한 인증 처리는 하지 않는다.
        // oauth2Login -> 최종 사용자에 대한 인증 및 인가 처리까지 진행한다.

        httpSecurity.authorizeRequests((requests) -> requests.antMatchers("/login").permitAll().anyRequest().authenticated())
                .oauth2Login(
                        (oauth2) -> oauth2
                                //.loginPage("/login") login Page Custom이 필요할때 주석 해지 !
                                .authorizationEndpoint(authorizationEndpointConfig ->
                                        authorizationEndpointConfig.baseUri("/oauth2/v1/authorization"))
                                // loginProcessingUrl 보다 우선순위가 높다
                                .redirectionEndpoint(redirectionEndpointConfig ->
                                        redirectionEndpointConfig.baseUri("/login/v1/oauth2/code/*"))
                )

                .logout()
                .logoutSuccessUrl("/login");

        httpSecurity
                .exceptionHandling()
                .authenticationEntryPoint(oauth2AuthenticationEntryPoint)
                .and()
                .logout()
                .logoutSuccessHandler(oidcLogOutSuccessHandler())
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .deleteCookies("JSESSIONID");

        return httpSecurity.build();
    }
    **/

    @Bean
    WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().antMatchers("/js/**", "/css/**", "/images/**", "/favicon.ico");
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

        httpSecurity.authorizeRequests((requests) ->
                requests.antMatchers("/home", "/client").permitAll().anyRequest().authenticated())
                .oauth2Client(Customizer.withDefaults())
                .logout()
                .logoutSuccessUrl("/home");

        return httpSecurity.build();
    }

    private OAuth2AuthorizationRequestResolver customOAuth2AuthenticationRequestResolver() {
        return new CustomOAuth2AuthorizationRequestResolver(clientRegistrationRepository, "/oauth2/authorization");
    }
}
