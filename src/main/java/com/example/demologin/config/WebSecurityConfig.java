package com.example.demologin.config;

import com.example.demologin.auth.LoginFailureHandler;
import com.example.demologin.auth.LoginFailureListener;
import com.example.demologin.auth.LoginSuccessListener;
import com.example.demologin.auth.PrincipalDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

@Configuration
@EnableWebSecurity
//@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private PrincipalDetailsService principalDetailsService;

    /*@Autowired
    private LoginFailureHandler loginFailureHandler;*/

    /*@Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }*/

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        return new LoginFailureHandler();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.csrf().disable()
                .headers().frameOptions().disable()
                .and()
                    .authorizeRequests()
//                    .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                    .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                    .antMatchers("/").permitAll()
                    .antMatchers("/notice").permitAll()
                    .antMatchers("/board").permitAll()
                    .antMatchers("/join").permitAll()
                    .antMatchers("/joinOK").permitAll()
                    .antMatchers("/h2-console/**").permitAll()
                    .anyRequest().authenticated()
                .and()
                    .formLogin()
                    .loginPage("/login")
                    .loginProcessingUrl("/loginOK")
                    .defaultSuccessUrl("/")
                    .failureUrl("/notice")
//                    .failureHandler(authenticationFailureHandler)
                    .permitAll()
                .and()
                    .logout()
                    .logoutUrl("/logout")
//                    .logoutSuccessUrl("/login");
                    .logoutSuccessUrl("/board");
//                    .permitAll();



                /*.and()
                    .authorizeRequests()
                    .antMatchers("/").permitAll()
                    .antMatchers("/user/**").authenticated()
                    .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                    .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
//                .anyRequest().permitAll()

                .and()
                    .formLogin()
                    .loginPage("/login")
//                .successHandler(loginSuccess)
//                .usernameParameter("username2")
                    .loginProcessingUrl("/loginOK")
                    .defaultSuccessUrl("/")
                .and()
                    .logout()
                    .logoutUrl("/logout")
                    .logoutSuccessUrl("/login");
//                .failureForwardUrl("/fail");*/
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        super.configure(auth);
        auth.userDetailsService(principalDetailsService);
    }

   /*@Autowired
    private LoginService loginService;*/

    /*@Override
    protected void configure(HttpSecurity http) throws Exception {

           *//*http.csrf().disable()
                .headers().frameOptions().disable()
                .and()
                .authorizeRequests()
//                .antMatchers("/", "/css/**", "/images/**", "/js/**", "/h2-console/**").permitAll()
                .antMatchers("/", "/h2-console/**").permitAll()
//                .antMatchers("/api/v1/**").hasRole(Role.USER.name())
                .anyRequest().authenticated();*//*
                *//*.and()
                .logout()
                .logoutSuccessUrl("/")
                .and()
                .oauth2Login()
                .userInfoEndpoint()
                .userService(customOAuth2UserService);*//*

//        super.configure(http);
    }*/

    /*@Override
    public void configure(WebSecurity web) throws Exception {
//        super.configure(web);
        web.ignoring().antMatchers("/css/**", "/js/**", "/images/**");
    }

    */

    /*@Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        super.configure(auth);
        auth.userDetailsService(loginService).passwordEncoder(passwordEncoder());
    }*/
}
