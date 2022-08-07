package org.vrex.recognito.demo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.vrex.recognito.demo.model.recognito.RecognitoClient;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class TokenValidationFilter extends OncePerRequestFilter {

    private static final String INVALID_CREDENTIALS_ERROR = "Credentials provided are not authorized";

    @Autowired
    private RecognitoClient recognitoClient;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String resource = request.getServletPath();

        if (ObjectUtils.isEmpty(recognitoClient.getLoggedInUser().getToken()))
            recognitoClient.generateTokenForLoggedInUser();

        if (!recognitoClient.authorizeUser(resource)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        } else
            response.setStatus(HttpServletResponse.SC_ACCEPTED);

        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return request.getServletPath().equals("/user/login");
    }

}
