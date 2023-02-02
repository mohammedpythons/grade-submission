package com.ltp.gradesubmission.security.filter;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ltp.gradesubmission.entity.User;
import com.ltp.gradesubmission.security.SecurityConstants;
import com.ltp.gradesubmission.security.manager.CustomAuthenticationManager;

import lombok.AllArgsConstructor;

@AllArgsConstructor
public class AuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private CustomAuthenticationManager customAuthenticationManager;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
                //1- get the values that is coming inside the request by doing request.getInputStream()
                //2- use object mapper to create an object that corrsponds
                // to the User object with the values that are coming from the request
                try {
                    User user = new ObjectMapper().readValue(request.getInputStream(), User.class);
                    Authentication authentication = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
                    return customAuthenticationManager.authenticate(authentication);
                } catch (IOException e) {
                    // we are throwing runtime exception because
                    // if the user were to pass invalid fields name it is impossible to map into the properties of a user class
                    throw new RuntimeException();

                }

    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
            Authentication authResult) throws IOException, ServletException {
                String token = JWT.create()
                .withSubject(authResult.getName())
                .withExpiresAt(new Date(System.currentTimeMillis()+ SecurityConstants.TOKEN_EXPIRATION))
                .sign(Algorithm.HMAC512(SecurityConstants.SECRET_KEY));
                System.out.println("token" + token);
                response.addHeader(SecurityConstants.AUTHORIZATION, SecurityConstants.BEARER + token);

    }
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException failed) throws IOException, ServletException {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write(failed.getMessage());
                response.getWriter().flush();
    }

}
