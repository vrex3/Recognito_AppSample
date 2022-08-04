package org.vrex.recognito.demo.config;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.vrex.recognito.demo.model.LoggedInUser;
import org.vrex.recognito.demo.model.User;

import java.util.Arrays;

@Component
public class UserAuthProvider implements AuthenticationProvider {

    private static final String INVALID_CREDENTIALS_ERROR = "Credentials provided are not valid";

    @Autowired
    private User loggedInUser;

    /**
     * Authenticates the provided credentials against Recognito
     *
     * @param authentication
     * @return
     * @throws AuthenticationException
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        loggedInUser.setUpRestTemplate(authentication);
        loggedInUser.loginUser();
        LoggedInUser user = loggedInUser.getUser();

        if (user != null) {
            return new UsernamePasswordAuthenticationToken(user.getUsername(),
                    authentication.getCredentials().toString(),
                    Arrays.asList(new SimpleGrantedAuthority(user.getRole())));
        } else {
            throw new BadCredentialsException(INVALID_CREDENTIALS_ERROR);
        }
    }

    @Override
    public boolean supports(Class<?> authenticationType) {
        return authenticationType.equals(UsernamePasswordAuthenticationToken.class);
    }
}
