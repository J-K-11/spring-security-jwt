package com.test.springsecurity.controller;

import com.test.springsecurity.model.AuthenticationRequest;
import com.test.springsecurity.util.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthenticationController {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    JwtTokenUtil jwtTokenUtil;

    @PostMapping(value="/authenticate")
    public String authenticate(@RequestBody AuthenticationRequest request){
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken
                (request.getUsername(), request.getPassword()));
        UserDetails user = (UserDetails) authentication.getPrincipal();
        return jwtTokenUtil.generateToken(user);

    }
}
