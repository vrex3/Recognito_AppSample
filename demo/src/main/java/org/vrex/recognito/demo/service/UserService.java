package org.vrex.recognito.demo.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.ObjectUtils;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.vrex.recognito.demo.model.LoggedInUser;

import java.util.HashMap;
import java.util.Map;


@Slf4j
@Component
@Scope(value = "session", proxyMode = ScopedProxyMode.TARGET_CLASS)
public class UserService implements InitializingBean {

    private static final String SESSION_COOKIE = "JSESSIONID";
    public static final String APP_UUID = "x-app-uuid";
    public static final String APP_TOKEN = "x-auth-token";
    private static final String RESOURCE = "resource";

    private RestTemplate restTemplate;
    private ObjectMapper mapper;

    @Value("${recognito.host.url}")
    private String recognitoHost;

    private LoggedInUser user = null;
    private boolean userLoggedIn = false;
    private String jsessionID = null;
    private String token = null;

    @Override
    public void afterPropertiesSet() throws Exception {
        Authentication authentication = getAuthenticationPrinicipal();
        restTemplate = new RestTemplateBuilder()
                .basicAuthentication(authentication.getName(), authentication.getCredentials().toString())
                .build();
    }

    /**
     * Logs in an user if credentials are proper.
     * Call from authentication provider
     *
     * @return
     */
    public LoggedInUser authenticateUser() {
        try {
            if (user == null || !userLoggedIn) {
                loginAuthenticatedUser();
                userLoggedIn = !ObjectUtils.isEmpty(user);
            }
        } catch (RestClientException exception) {
            exception.printStackTrace();
        }
        return user;
    }

    /**
     * Returns the logged in authentication principle
     *
     * @return
     */
    private Authentication getAuthenticationPrinicipal() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    private void loginAuthenticatedUser() {

        this.user = (LoggedInUser) executeGET(recognitoHost + "/app/user/login", LoggedInUser.class);
        this.token = executeGET(recognitoHost + "/app/user/token/generate", String.class).toString();

    }

    public boolean authorizeUser(String resource) {
        Map<String, String> uriVariables = new HashMap<>();
        uriVariables.put(RESOURCE, resource);

        MultiValueMap<String, String> headerParams = new LinkedMultiValueMap<>();
        headerParams.add(APP_UUID, user.getAppUUID());
        headerParams.add(APP_TOKEN, token);

        HttpEntity entity = buildHttpEntity();
        entity.getHeaders().addAll(headerParams);


        Object response = executeGET(recognitoHost + "/app/user/token/authorize", LoggedInUser.class, entity, uriVariables);
        return response != null;
    }

    private <T> Object executeGET(String url, Class<T> clazz) {
        ResponseEntity response = restTemplate.exchange(url, HttpMethod.GET, buildHttpEntity(), clazz);
        setSessionCookie(response);
        return response.hasBody() ? response.getBody() : null;
    }

    private <T> Object executeGET(String url, Class<T> clazz, HttpEntity entity, Map<String, String> uriVariables) {
        ResponseEntity response = restTemplate.exchange(url, HttpMethod.GET, buildHttpEntity(), clazz, uriVariables);
        setSessionCookie(response);
        return response.hasBody() ? response.getBody() : null;
    }

    private HttpEntity buildHttpEntity() {
        HttpHeaders requestHeaders = new HttpHeaders();
        HttpEntity request = null;

        if (this.jsessionID != null) {
            requestHeaders.add(SESSION_COOKIE, jsessionID);
            request = new HttpEntity<>(requestHeaders);
        }

        return request;
    }

    private void setSessionCookie(ResponseEntity response) {
        if (response != null && response.getStatusCode() == HttpStatus.OK)
            this.jsessionID = response.getHeaders().getFirst(SESSION_COOKIE);
    }
}
