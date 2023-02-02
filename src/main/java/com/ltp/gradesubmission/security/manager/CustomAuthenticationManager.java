package com.ltp.gradesubmission.security.manager;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import com.ltp.gradesubmission.entity.User;
import com.ltp.gradesubmission.service.UserService;

import lombok.AllArgsConstructor;



@Component
@AllArgsConstructor
public class CustomAuthenticationManager implements AuthenticationManager {
    private UserService userService;
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // get the user by the authentication
        User user = userService.getUser(authentication.getName());
        // check for the user password
        if (!bCryptPasswordEncoder.matches(authentication.getCredentials().toString(), user.getPassword())){
            throw new BadCredentialsException("Invalid credentials!");
        }
        // do the jwt settings here or call another class

        return new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
    }

}
