package com.spring.oauth2.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;

@Log4j2
@Controller
@RequiredArgsConstructor
public class OAuth2ClientController {

    private final OAuth2AuthorizedClientService service;
    private final OAuth2AuthorizedClientRepository repository;

    @GetMapping("/client")
    public ModelAndView client(HttpServletRequest request) {
        // 인증처리 로직.
        ModelAndView modelAndView = new ModelAndView("client");

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String clientRegistrationId = "keycloak";

        OAuth2AuthorizedClient oAuth2AuthorizedClientByService = service.loadAuthorizedClient(clientRegistrationId, authentication.getName());

        OAuth2AuthorizedClient oAuth2AuthorizedClient = repository.loadAuthorizedClient(clientRegistrationId, authentication, request);

        OAuth2AccessToken oAuth2AccessToken = oAuth2AuthorizedClient.getAccessToken();

        OAuth2UserService oAuth2UserService = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = oAuth2UserService.loadUser(new OAuth2UserRequest(oAuth2AuthorizedClient.getClientRegistration(), oAuth2AccessToken));

        OAuth2AuthenticationToken authenticationToken = new OAuth2AuthenticationToken(oAuth2User, Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")), oAuth2AuthorizedClient.getClientRegistration().getRegistrationId());
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);

        modelAndView.addObject("principalName", oAuth2User.getName());
        modelAndView.addObject("clientName", oAuth2AuthorizedClient.getClientRegistration().getClientName());
        modelAndView.addObject("accessToken", oAuth2AccessToken.getTokenValue());
        modelAndView.addObject("refreshToken", oAuth2AuthorizedClient.getRefreshToken().getTokenValue());

        return modelAndView;
    }
}
