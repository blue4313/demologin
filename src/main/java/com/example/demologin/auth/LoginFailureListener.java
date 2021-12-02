package com.example.demologin.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.stereotype.Service;

@Service
public class LoginFailureListener implements ApplicationListener<AuthenticationFailureBadCredentialsEvent> {

    Logger logger = LoggerFactory.getLogger(LoginFailureListener.class);

    @Override
    public void onApplicationEvent(AuthenticationFailureBadCredentialsEvent event) {
        String username = (String)event.getAuthentication().getPrincipal();
        String password = (String)event.getAuthentication().getCredentials();
        logger.info("접속실패 : " + username + " / " + password);
    }
}
