package com.staroot.sso;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class ApiController {

    @GetMapping("/hello")
    public String hello(@RequestHeader("Authorization") String token) {
        System.out.println("token:"+token);
        if (JwtUtil.validateToken(token)) {
            String username = JwtUtil.getUsernameFromToken(token);
            return "(SSO Server) Hello, " + username + "!";
        } else {
            return "(SSO Server) Invalid token!";
        }
    }
    @GetMapping("/jwtByCookie")
    public String jwtByCookie(HttpServletRequest request) {
        String jwtToken = getJwtTokenFromCookie(request);
        String token = jwtToken;
        System.out.println("token:"+token);
        if (JwtUtil.validateToken(token)) {
            String username = JwtUtil.getUsernameFromToken(token);
            return "(SSO Server) Hello, Your jwt token valid! " + username + "!";
        } else {
            return "(SSO Server) Invalid token!";
        }
    }
    private String getJwtTokenFromCookie(HttpServletRequest request) {
        // 쿠키에서 jwtToken 값을 찾아 반환
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("jwtToken".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password) {
        // Perform authentication logic (e.g., check username and password against database)

        // Assuming authentication is successful, generate and return a JWT
        System.out.println( "(SSO Server) Hello, " + username + "!");
        String jwtToken = JwtUtil.generateToken(username);
        System.out.println( "(SSO Server) jwtToken :: " + jwtToken + "!");
        return jwtToken;
    }
}
