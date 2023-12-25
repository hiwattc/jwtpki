package com.staroot.sso;
import io.jsonwebtoken.*;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
public class JwtUtil {

    private static final String PRIVATE_KEY_FILE = "private_key.pem";
    private static final String PUBLIC_KEY_FILE = "public_key.pem";

    private static final PrivateKey PRIVATE_KEY = KeyUtils.readPrivateKeyFromFile(PRIVATE_KEY_FILE);
    private static final PublicKey PUBLIC_KEY = KeyUtils.readPublicKeyFromFile(PUBLIC_KEY_FILE);
    //private static final long EXPIRATION_TIME = 86400000; // 만료 시간 24시간(ms 단위)
    private static final long EXPIRATION_TIME = 60000; // 만료 시간 60초
    public static String generateToken(String username) {
        Date now = new Date();
        Date expiration = new Date(now.getTime() + EXPIRATION_TIME);

        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(expiration)
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
