package org.vrex.recognito.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
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
    private RecognitoClient loggedInUser;

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
        LoggedInUser user = loggedInUser.getLoggedInUser();

        response.addHeader(RecognitoClient.APP_TOKEN, user.getToken());
        return new ResponseEntity<>(user.getUserDetails(), HttpStatus.OK);
    }

    /**
     * Authorizes logged in user against API path (treated as resource)
     *
     * @return
     */
    @GetMapping(value = "/authorize/resource1")
    public ResponseEntity<?> authorize() {
        return new ResponseEntity<>(loggedInUser.getLoggedInUser(), HttpStatus.OK);
    }
}
