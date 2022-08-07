package org.vrex.recognito.demo.config;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.vrex.recognito.demo.model.recognito.LoggedInUser;
import org.vrex.recognito.demo.model.recognito.RecognitoClient;

import java.util.Arrays;

@Component
public class UserAuthProvider implements AuthenticationProvider {

    private static final String INVALID_CREDENTIALS_ERROR = "Credentials provided are not valid";

    @Autowired
    private RecognitoClient recognitoClient;

    /**
     * Authenticates the provided credentials against Recognito
     *
     * @param authentication
     * @return
     * @throws AuthenticationException
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        recognitoClient.setUpRestTemplate(authentication);
        recognitoClient.loginAuthenticatedUser();
        LoggedInUser user = recognitoClient.getLoggedInUser();

        if (!ObjectUtils.isEmpty(user) &&
                !ObjectUtils.isEmpty(user.getUserDetails())) {

            return new UsernamePasswordAuthenticationToken(
                    user.getUserDetails().getUsername(),
                    authentication.getCredentials().toString(),
                    Arrays.asList(new SimpleGrantedAuthority(user.getUserDetails().getRole())));
        } else {
            throw new BadCredentialsException(INVALID_CREDENTIALS_ERROR);
        }
    }

    @Override
    public boolean supports(Class<?> authenticationType) {
        return authenticationType.equals(UsernamePasswordAuthenticationToken.class);
    }
}
