package org.vrex.recognito.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.vrex.recognito.demo.model.recognito.RecognitoClient;

@RestController
@RequestMapping(value = "/user")
@SuppressWarnings("unused")
public class UserController {

    @Autowired
    private RecognitoClient loggedInUser;

    @GetMapping(value = "/login")
    public ResponseEntity<?> loginUser() {
        return new ResponseEntity<>(loggedInUser.getLoggedInUser().getUserDetails(), HttpStatus.OK);
    }

    @GetMapping(value = "/authorize/resource1")
    public ResponseEntity<?> authorize() {
        return new ResponseEntity<>(loggedInUser.getLoggedInUser(), HttpStatus.OK);
    }
}
