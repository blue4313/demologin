package com.example.demologin.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class LoginSuccessListener implements ApplicationListener<AuthenticationSuccessEvent> {

    Logger logger = LoggerFactory.getLogger(LoginSuccessListener.class);

    @Override
    public void onApplicationEvent(AuthenticationSuccessEvent event) {
        String username = ((UserDetails)(event.getAuthentication().getPrincipal())).getUsername();
        String password = ((UserDetails)(event.getAuthentication().getPrincipal())).getPassword();
        logger.info("접속성공 : " + username + " / " + password);
    }
}
