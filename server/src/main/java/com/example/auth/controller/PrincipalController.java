package com.example.auth.controller;

import java.security.Principal;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PrincipalController {
    
    @RequestMapping("/me")
    public Principal me(Principal principal) {
        return principal;
    }
        
}
