package org.vrex.recognito.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.vrex.recognito.demo.model.recognito.LoggedInUser;
import org.vrex.recognito.demo.model.recognito.RecognitoClient;

import javax.servlet.http.HttpServletResponse;

@RestController
@RequestMapping(value = "/user")
@SuppressWarnings("unused")
public class UserController {

    @Autowired
    private RecognitoClient recognitoClient;

    /**
     * Logs in user
     * Generates Recognito access token on successful login
     * Sets user recognito access token as part of response header
     *
     * @param response
     * @return
     */
    @GetMapping(value = "/login")
    public ResponseEntity<?> loginUser(HttpServletResponse response) {
        LoggedInUser user = recognitoClient.getLoggedInUser();

        response.addHeader(RecognitoClient.APP_TOKEN, user.getToken());
        return new ResponseEntity<>(user.getUserDetails(), HttpStatus.OK);
    }

    /**
     * SAMPLE AUTH APIs for testing/demo purposes
     * Access list
     * /authorize/resource/1 -> APP_DEVELOPER
     * /authorize/resource/2 -> APP_ADMIN,APP_DEVELOPER
     * /authorize/resource/3 -> APP_USER
     * /authorize/resource/4 -> APP_DEVELOPER,APP_USER
     */

    /**
     * Authorizes logged in user against API path (treated as resource)
     *
     * @param response
     * @param resourceId
     * @return
     */
    @GetMapping(value = "/authorize/resource/{resourceId}")
    public ResponseEntity<?> authorize(HttpServletResponse response,
                                       @PathVariable String resourceId) {
        return recognitoClient.buildAuthResponse(response);
    }
}
