package com.example.demologin.auth;

import com.example.demologin.entity.User;
import com.example.demologin.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class PrincipalDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("username : " + username);
        User user = userRepository.findByUsername(username);

//        return new PrincipalDetails(user);

        if (user == null) {
            throw new UsernameNotFoundException(username);
//            return new PrincipalDetails(user);
        } else {
            return new PrincipalDetails(user);
        }
    }
}
