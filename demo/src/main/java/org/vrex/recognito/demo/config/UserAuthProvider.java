package org.vrex.recognito.demo.config;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.vrex.recognito.demo.model.LoggedInUser;
import org.vrex.recognito.demo.service.UserService;

import java.util.Arrays;

@Component
public class UserAuthProvider implements AuthenticationProvider {

    @Autowired
    private UserService userService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        LoggedInUser user = userService.authenticateUser();
        if (user != null) {
            //log.info("{} User Authenticated - {}", LOG_TEXT, username);
            return new UsernamePasswordAuthenticationToken(user.getUsername(), authentication.getCredentials().toString(), Arrays.asList(new SimpleGrantedAuthority(user.getRole())));
        } else {
            //log.error("{} Invalid credentials for user - {}", LOG_TEXT, username);
            throw new BadCredentialsException("invalid creds");
        }
    }

    @Override
    public boolean supports(Class<?> authenticationType) {
        return authenticationType.equals(UsernamePasswordAuthenticationToken.class);
    }
}
