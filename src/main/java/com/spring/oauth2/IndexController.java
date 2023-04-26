package com.spring.oauth2;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Log4j2
@RestController
@RequiredArgsConstructor
@RequestMapping("/")
public class IndexController {

    private final ClientRegistrationRepository repository;

    @GetMapping
    public String index(@AuthenticationPrincipal OAuth2User oAuth2User) {
        log.info("oAuth2User : " + oAuth2User);
        return "index";
    }

    @GetMapping("oauth2/user")
    public OAuth2User oAuth2User(String accessToken) {
        if (StringUtils.isNotBlank(accessToken)) {
            ClientRegistration clientRegistration = repository.findByRegistrationId("keycloak");
            OAuth2AccessToken oAuth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, accessToken, Instant.now(), Instant.MAX);

            OAuth2UserRequest oAuth2UserRequest = new OAuth2UserRequest(clientRegistration, oAuth2AccessToken);
            DefaultOAuth2UserService service = new DefaultOAuth2UserService();
            return service.loadUser(oAuth2UserRequest);
        }

        return null;
    }

    @GetMapping("oidc/user")
    public OidcUser oidcUser(String idToken, String accessToken) {
        if (StringUtils.isNotBlank(idToken) && StringUtils.isNotBlank(accessToken)) {
            ClientRegistration clientRegistration = repository.findByRegistrationId("keycloak");
            OAuth2AccessToken oAuth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, accessToken, Instant.now(), Instant.MAX);

            Map<String, Object> claims = new HashMap<>();
            claims.put(IdTokenClaimNames.ISS, "http://localhost:9090/realms/oauth2");
            claims.put(IdTokenClaimNames.SUB, "OIDC");
            claims.put("preferred_username", "user");

            OidcIdToken oidcIdToken = new OidcIdToken(idToken, Instant.now(), Instant.MAX, claims);

            OidcUserRequest oidcUserRequest = new OidcUserRequest(clientRegistration, oAuth2AccessToken, oidcIdToken);
            OidcUserService service = new OidcUserService();
            return service.loadUser(oidcUserRequest);
        }

        return null;
    }

    /**
    @GetMapping("oauth2/authentication")
    public OAuth2User oAuth2User(@AuthenticationPrincipal OAuth2User oAuth2User) {
        log.info("oAuth2User : " + oAuth2User);
        return oAuth2User;
    }

    @GetMapping("oauth2/authentication")
    public OidcUser oidcUser(@AuthenticationPrincipal OidcUser oidcUser) {
        // scope에 openid가 없으면 oidcUser 객체는 null
        log.info("oidcUser : " + oidcUser);
        return oidcUser;
    }
    **/
}
