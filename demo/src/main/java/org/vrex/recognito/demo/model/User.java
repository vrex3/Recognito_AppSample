package org.vrex.recognito.demo.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

/**
 * This bean maintains information of logged in user.
 * Also maintains the JSESSION ID recieved from Recognito for stateful API calls.
 * This session ID is stored for future authentication purposes for same user.
 * All operations in this bean are carried out within the scope of a single session.
 * Since this bean is session scoped, it will maintain it's data for ALL APIs that this demo
 * application classifies as Stateful in Config
 */
@Slf4j
@Data
@AllArgsConstructor
@NoArgsConstructor
@Component
@Scope(value = "session", proxyMode = ScopedProxyMode.TARGET_CLASS)
public class User implements InitializingBean {

    private static final String SESSION_COOKIE_REQUEST_KEY = "Cookie";
    private static final String SESSION_COOKIE_RESPONSE_KEY = "Set-Cookie";
    private static final String APP_UUID = "x-app-uuid";
    private static final String APP_TOKEN = "x-auth-token";
    private static final String RESOURCE = "resource";

    @Value("${recognito.host.url}")
    private String recognitoHost;

    private RestTemplate restTemplate;

    private LoggedInUser user = null;
    private String jsessionID = null;

    @Override
    public void afterPropertiesSet() throws Exception {
        /*forces property set*/
        log.info("Session Bean created to manage user login session");
    }

    /**
     * Default constructor called from auth provider to log in user.
     * RestTemplate is initialed for session with basic authentication
     * username and password extracted from Spring Authentication object.
     * User is attempted to be logged in to Recognito.
     * If log in is successful, token is generated for user from recognito.
     * ALl information for user is maintained in this session scoped bean.
     *
     * @param authentication
     */
    public void setUpRestTemplate(Authentication authentication) {

        this.restTemplate = new RestTemplateBuilder()
                .basicAuthentication(authentication.getName(), authentication.getCredentials().toString())
                .build();
    }

    /**
     * Logs in user and persists logged in user data
     */
    public void loginUser() {
        try {
            loginAuthenticatedUser();
        } catch (RestClientException exception) {
            exception.printStackTrace();
        } catch (Exception exception) {
            exception.printStackTrace();
        }
    }

    /**
     * Authorizes the logged in user against a passed resource
     *
     * @param resource
     * @return
     */
    public boolean authorizeUser(String resource) {
        Map<String, String> uriVariables = new HashMap<>();
        uriVariables.put(RESOURCE, resource);

        MultiValueMap<String, String> headerParams = new LinkedMultiValueMap<>();
        headerParams.add(APP_UUID, user.getAppUUID());
        headerParams.add(APP_TOKEN, user.getRecognitoToken().getToken());

        HttpEntity entity = getHttpEntityWithJsessionCookie();
        entity.getHeaders().addAll(headerParams);


        Object response = executeGET(recognitoHost + "/app/user/token/authorize", LoggedInUser.class, entity, uriVariables);
        return response != null;
    }

    /**
     * PRIVATE UTILITY METHODS
     */

    /**
     * Logs in user in Recognito with credentials provided to demo
     * If user is logged in (response data and 200 status code), asks Recognito to generate token for user
     * Token is stored in this bean for further authorizations
     */
    private void loginAuthenticatedUser() {
        ResponseEntity userLoginResponse = executeGET(recognitoHost + "/app/user/login", LoggedInUser.class);
        if (userLoginResponse.getStatusCode().equals(HttpStatus.OK) && userLoginResponse.hasBody()) {
            this.user = (LoggedInUser) userLoginResponse.getBody();
            generateTokenForLoggedInUser();

        }
    }

    /**
     * Generate token from Recognito for logged in user
     * Stores token in session bean
     */
    private void generateTokenForLoggedInUser() {
        ResponseEntity tokenResponse = executeGET(recognitoHost + "/app/user/token/generate", UserToken.class);
        if (tokenResponse.getStatusCode().equals(HttpStatus.OK) && tokenResponse.hasBody()) {
            this.user.setRecognitoToken((UserToken) tokenResponse.getBody());
        }
    }

    /**
     * Executes Http GET against provided Recognito URL with
     * no params and no httpEntity
     *
     * @param url
     * @param clazz
     * @param <T>
     * @return
     */
    private <T> ResponseEntity executeGET(String url, Class<T> clazz) {
        ResponseEntity response = restTemplate.exchange(url, HttpMethod.GET, getHttpEntityWithJsessionCookie(), clazz);
        setSessionCookie(response);
        return response;
    }

    /**
     * Executes Http GET against provided Recognito URL
     * with Params and HttpEntity
     *
     * @param url
     * @param clazz
     * @param entity
     * @param uriVariables
     * @param <T>
     * @return
     */
    private <T> ResponseEntity executeGET(String url, Class<T> clazz, HttpEntity entity, Map<String, String> uriVariables) {
        ResponseEntity response = restTemplate.exchange(url, HttpMethod.GET, entity, clazz, uriVariables);
        setSessionCookie(response);
        return response;
    }

    /**
     * Adds JSESSION cookie to http entity if present
     * JSESSION cookie obtained from previous Recognito responses in same session
     *
     * @return
     */
    private HttpEntity getHttpEntityWithJsessionCookie() {
        HttpHeaders requestHeaders = new HttpHeaders();
        HttpEntity request = null;

        if (this.jsessionID != null) {
            requestHeaders.add(SESSION_COOKIE_REQUEST_KEY, jsessionID);
            request = new HttpEntity<>(requestHeaders);
        }

        return request;
    }

    /**
     * Extracts a JSESSIONID cookie from response
     * Cookie is under header Set-Cookie
     * Cookie format is JSESSIONID=2155*******54F75DFC036; Path=/; HttpOnly
     * Cookie to be parsed till first occurence of ;
     *
     * @param response
     */
    private void setSessionCookie(ResponseEntity response) {
        if (response != null && response.getStatusCode() == HttpStatus.OK) {
            this.jsessionID = response.getHeaders().getFirst(SESSION_COOKIE_RESPONSE_KEY);
            if (this.jsessionID != null)
                jsessionID = jsessionID.substring(0, jsessionID.indexOf(";"));
        }
    }


}
