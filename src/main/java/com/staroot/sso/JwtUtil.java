package com.staroot.sso;
import io.jsonwebtoken.*;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;

public class JwtUtil {

    private static final String PRIVATE_KEY_FILE = "private_key.pem";
    private static final String PUBLIC_KEY_FILE = "public_key.pem";

    private static final PrivateKey PRIVATE_KEY = KeyUtils.readPrivateKeyFromFile(PRIVATE_KEY_FILE);
    private static final PublicKey PUBLIC_KEY = KeyUtils.readPublicKeyFromFile(PUBLIC_KEY_FILE);

    public static String generateToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .signWith(SignatureAlgorithm.RS256, PRIVATE_KEY)
                .compact();
    }

    public static String getUsernameFromToken(String token) {
        return Jwts.parserBuilder().setSigningKey(PUBLIC_KEY).build().parseClaimsJws(token).getBody().getSubject();
    }

    public static boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(PUBLIC_KEY).build().parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public static void main(String[] args) {
        // 토큰 생성
        String token = generateToken("username");
        System.out.println("Generated Token: " + token);

        // 토큰 검증
        boolean isValid = validateToken(token);
        System.out.println("Is Valid Token? " + isValid);

        // 토큰에서 사용자명 추출
        String username = getUsernameFromToken(token);
        System.out.println("Username from Token: " + username);
    }
}
