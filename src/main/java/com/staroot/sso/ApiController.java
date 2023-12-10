package com.staroot.sso;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class ApiController {

    @GetMapping("/hello")
    public String hello(@RequestHeader("Authorization") String token) {
        System.out.println("token:"+token);
        if (JwtUtil.validateToken(token)) {
            String username = JwtUtil.getUsernameFromToken(token);
            return "Hello, " + username + "!";
        } else {
            return "Invalid token!";
        }
    }

    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password) {
        // Perform authentication logic (e.g., check username and password against database)

        // Assuming authentication is successful, generate and return a JWT
        return JwtUtil.generateToken(username);
    }
}
