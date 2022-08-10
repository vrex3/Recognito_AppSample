package org.vrex.recognito.demo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.vrex.recognito.demo.model.Role;

@Configuration
@EnableWebSecurity
@SuppressWarnings("unused")
public class SecurityConfig {

    private AuthenticationManager authenticationManager;

    @Autowired
    private UserAuthProvider userAuthenticationProvider;

    @Autowired
    private TokenValidationFilter authFilter;

    @Bean
    public SecurityFilterChain filterChainStateful(HttpSecurity http) throws Exception {

        try {
            AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
            authenticationManagerBuilder.authenticationProvider(userAuthenticationProvider);
            authenticationManager = authenticationManagerBuilder.build();

            http.cors()
                    .and()
                    .csrf().disable()


                    .addFilterAfter(authFilter, AuthorizationFilter.class)
                    .authenticationManager(authenticationManager).sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
                    .and()
                    .authorizeRequests()

                    .antMatchers(HttpMethod.POST, "/user/register").permitAll()
                    .antMatchers(HttpMethod.POST, "/user/authorize/resource/**").hasAnyAuthority(Role.APP_ADMIN.name(), Role.APP_DEVELOPER.name(), Role.APP_USER.name())
                    .antMatchers(HttpMethod.GET, "/user/login").hasAnyAuthority(Role.APP_ADMIN.name(), Role.APP_DEVELOPER.name(), Role.APP_USER.name())
                    .antMatchers(HttpMethod.GET, "/user/authorize/resource/**").hasAnyAuthority(Role.APP_ADMIN.name(), Role.APP_DEVELOPER.name(), Role.APP_USER.name())

                    .anyRequest()
                    .authenticated()
                    .and()
                    .formLogin()
                    .and()
                    .httpBasic();

        } catch (Exception exception) {
            exception.printStackTrace();
        }

        return http.build();
    }

}
