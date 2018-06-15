package com.oauth.resource.controller;

import java.security.Principal;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {
    
    @GetMapping("/home")
    public Message home(Principal principal) {
        return new Message(principal.getName());
    }
    
    @Data
    @AllArgsConstructor
    public static class Message {
        private String name;
    }
    
}
