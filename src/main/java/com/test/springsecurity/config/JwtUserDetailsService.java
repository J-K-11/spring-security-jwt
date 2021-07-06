package com.test.springsecurity.config;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class JwtUserDetailsService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
        if(userName.equals("jasleen")){
            return new User("jasleen", "$2a$10$xZj9xaoSI/hPGVFKRGGEw.UcfDCu7/hXlr3pN/Gna1nTH.4uM9CZO", new ArrayList<>());
        }else{
            throw new UsernameNotFoundException("Bad credentials");
        }


    }
}
