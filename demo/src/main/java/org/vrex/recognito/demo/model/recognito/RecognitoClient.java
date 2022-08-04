package org.vrex.recognito.demo.model.recognito;

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
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.vrex.recognito.demo.model.ApplicationException;

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
public class RecognitoClient implements InitializingBean {

    @Value("${recognito.host.url}")
    private String recognitoHost;

    private LoggedInUser loggedInUser;

    @Override
    public void afterPropertiesSet() throws Exception {
        /*forces property set*/
        log.info("Session Bean created to manage user login session");
    }

    /**
     * Setup method called from auth provider to setup rest template
     * RestTemplate is initialed for session with basic authentication
     *
     * @param authentication
     */
    public void setUpRestTemplate(Authentication authentication) {
        this.loggedInUser = new LoggedInUser();
        this.loggedInUser.setRestTemplate(new RestTemplateBuilder()
                .basicAuthentication(authentication.getName(), authentication.getCredentials().toString())
                .build());
    }

    /**
     * Logs in user in Recognito with credentials provided to demo
     * User credentials already stored as basic auth in rest template
     * If user is logged in (response data and 200 status code), asks Recognito to generate token for user
     * Token is stored in this bean for further authorizations
     */
    public void loginAuthenticatedUser() {
        ResponseEntity userLoginResponse = executeGET(recognitoHost + "/app/user/login", UserDetails.class);
        if (userLoginResponse.getStatusCode().equals(HttpStatus.OK) && userLoginResponse.hasBody()) {
            this.loggedInUser.setUserDetails((UserDetails) userLoginResponse.getBody());
            generateTokenForLoggedInUser();

        }
    }

    /**
     * Generate token from Recognito for logged in user
     * Stores token in session bean
     */
    public void generateTokenForLoggedInUser() {
        ResponseEntity tokenResponse = executeGET(recognitoHost + "/app/user/token/generate", UserToken.class);
        if (tokenResponse.getStatusCode().equals(HttpStatus.OK) && tokenResponse.hasBody()) {
            this.loggedInUser.setToken(((UserToken) tokenResponse.getBody()).getToken());
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
        headerParams.add(APP_UUID, loggedInUser.getUserDetails().getAppUUID());
        headerParams.add(APP_TOKEN, loggedInUser.getToken());

        HttpEntity entity = getHttpEntityWithJsessionCookie(headerParams);

        ResponseEntity response = executeGET(recognitoHost + "/app/user/token/authorize", UserDetails.class, entity, uriVariables);
        return response != null && response.getStatusCode().equals(HttpStatus.OK);
    }


    /**
     * PRIVATE UTILITY METHODS
     */

    private static final String SESSION_COOKIE_REQUEST_KEY = "Cookie";
    private static final String SESSION_COOKIE_RESPONSE_KEY = "Set-Cookie";
    private static final String APP_UUID = "x-app-uuid";
    private static final String APP_TOKEN = "x-auth-token";
    private static final String RESOURCE = "resource";

    private static final String CLIENT_EXCEPTION = "User is not authorized to perform the requested action";
    private static final String SERVER_EXCEPTION = "Recognito is not responding";

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

        ResponseEntity response = null;

        try {
            response = this.loggedInUser.getRestTemplate().exchange(url, HttpMethod.GET, getHttpEntityWithJsessionCookie(), clazz);
            setSessionCookie(response);
        } catch (HttpClientErrorException exception) { //4xx status code
            throw ApplicationException.builder()
                    .errorMessage(CLIENT_EXCEPTION)
                    .status(HttpStatus.FORBIDDEN)
                    .build();
        } catch (HttpServerErrorException exception) {
            throw ApplicationException.builder()
                    .errorMessage(SERVER_EXCEPTION)
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .build();

        }

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

        ResponseEntity response = null;

        try {
            response = this.loggedInUser.getRestTemplate().exchange(url, HttpMethod.GET, entity, clazz, uriVariables);
            setSessionCookie(response);
        } catch (HttpClientErrorException exception) { //4xx status code
            response = new ResponseEntity(HttpStatus.FORBIDDEN);
        } catch (HttpServerErrorException exception) {
            response = new ResponseEntity(HttpStatus.FORBIDDEN);
        }
        return response;
    }

    /**
     * Adds JSESSION cookie to http entity if present
     * JSESSION cookie obtained from previous Recognito responses in same session
     *
     * @return
     */
    private HttpEntity getHttpEntityWithJsessionCookie(MultiValueMap<String, String>... params) {
        HttpHeaders requestHeaders = new HttpHeaders();
        HttpEntity request = null;

        if (this.loggedInUser.getJsessionID() != null) {
            requestHeaders.add(SESSION_COOKIE_REQUEST_KEY, this.loggedInUser.getJsessionID());
            if (params.length > 0)
                requestHeaders.addAll(params[0]);

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
            String jsessionID = response.getHeaders().getFirst(SESSION_COOKIE_RESPONSE_KEY);
            if (jsessionID != null)
                this.loggedInUser.setJsessionID(jsessionID.substring(0, jsessionID.indexOf(";")));
        }
    }


}
