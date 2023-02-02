package com.ltp.gradesubmission.security.filter;

import java.io.IOException;


import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.ltp.gradesubmission.exception.EntityNotFoundException;

public class ExceptionHandlerFilter extends OncePerRequestFilter{

    public void responseMessage(HttpServletResponse res, String message, int status) throws IOException{
        res.setStatus(status);
        res.getWriter().write(message);
        res.getWriter().flush();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
                try {

                    filterChain.doFilter(request, response);
                }catch(JWTVerificationException e){
                    responseMessage(response, "Invalid JWT", HttpServletResponse.SC_BAD_REQUEST);

                }catch(EntityNotFoundException e){
                    responseMessage(response, "Username not found", HttpServletResponse.SC_NOT_FOUND);
                } catch (RuntimeException e) {
                    responseMessage(response, "Something went wrong!", HttpServletResponse.SC_BAD_REQUEST);
                }


    }


}
