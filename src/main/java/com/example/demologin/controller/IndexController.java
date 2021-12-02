package com.example.demologin.controller;

import com.example.demologin.entity.User;
import com.example.demologin.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class IndexController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    // localhost:8080/
    // localhost:8080
//    @GetMapping({"", "/"})
    @GetMapping("/")
    public String index() {
        return "index";
    }

    @GetMapping("/board")
    public String board() {
        return "board";
    }

    @GetMapping("/notice")
    public String notice() {
        return "notice";
    }

    @GetMapping("/user")
    public String user(Model model, Authentication authentication) {
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String username = userDetails.getUsername();
        model.addAttribute("username", username);
        return "user";
    }

    @GetMapping("/admin")
    public String admin() {
        return "admin";
    }

    @GetMapping("/manager")
    public String manager() {
        return "manager";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    /*@PostMapping("/loginProc")
    public String loginProc() {
        return "login";
    }*/

    @GetMapping("/join")
    public String join() {
        return "join";
    }

    @PostMapping("/joinOK")
    public String joinOK(User user) {
        System.out.println(user);

        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
//        user.setRole("ROLE_USER");
        user.setRole("ROLE_MANAGER");
        userRepository.save(user);

        return "joinOK";
    }
}


