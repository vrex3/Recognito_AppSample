package org.vrex.recognito.demo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.vrex.recognito.demo.model.recognito.RecognitoClient;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Set;

@Component
public class TokenValidationFilter extends OncePerRequestFilter {

    /**
     * Filter i.e. Authorization is applied only to this path.
     * Any other path is ignored.
     */
    private static final RequestMatcher APPLY_TO_PATH = new AntPathRequestMatcher("/user/authorize/resource/**");

    @Autowired
    private RecognitoClient recognitoClient;

    /**
     * Generates user token if not present in recognitoClient,
     * i.e. If user hits authorize API directly without logging in.
     * Token generation is authenticated, so user credentials are used and client is populated.
     * User is authorized treating the API path as the resource.
     * If response from authorizeUser is true, response status is set to 200 OK.
     * If response from authorizeUser is false, response status is set to 402 FORBIDDEN.
     *
     * @param request
     * @param response
     * @param filterChain
     * @throws ServletException
     * @throws IOException
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (APPLY_TO_PATH.matches(request)) {

            String resource = request.getServletPath();

            if (ObjectUtils.isEmpty(recognitoClient.getLoggedInUser().getToken()))
                recognitoClient.generateTokenForLoggedInUser();

            if (!recognitoClient.authorizeUser(resource)) {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            } else
                response.setStatus(HttpServletResponse.SC_ACCEPTED);
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Does not apply filter on this path.
     * User does not need to be authorized to login.
     * But user role is checked in security config.
     * User must have a role in the APP to access this API.
     * User needs to be created in recognito in order for user to login here.
     * Recognito user create API is free for all.
     * <p>
     * TODO : Add demo user creation API
     *
     * @param request
     * @return
     * @throws ServletException
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return request.getServletPath().equals("/user/login");
    }

}
