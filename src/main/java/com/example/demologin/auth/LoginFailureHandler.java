package com.example.demologin.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
public class LoginFailureHandler implements AuthenticationFailureHandler {

    Logger logger = LoggerFactory.getLogger(LoginSuccessListener.class);

    @Override
    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException authenticationException) throws IOException, ServletException {

        logger.info("LoginFailureHandler~~~~");

        /*String username = httpServletRequest.getParameter("username");
        String errormsg = authenticationException.getMessage();

        httpServletRequest.setAttribute("username", username);
        httpServletRequest.setAttribute("errormsg", errormsg);

        httpServletRequest.getRequestDispatcher("/login").forward(httpServletRequest, httpServletResponse);*/
    }
}
