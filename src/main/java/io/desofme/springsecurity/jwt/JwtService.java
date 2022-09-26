package io.desofme.springsecurity.jwt;

import io.desofme.springsecurity.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;

@Service
public class JwtService {

    @Value("${jwt.secret-key}")
    private String SECRET_KEY;

    @Value("${jwt.expiry-time}")
    private long EXPIRY_TIME;

    public String getToken(User user){
       String token =  Jwts.builder()
                .setSubject(user.getUsername())
                .setIssuedAt(new Date())
                .setIssuer("Desofme")
                .setExpiration(Date.from(Instant.now().plusSeconds(EXPIRY_TIME)))
                .signWith(SignatureAlgorithm.HS512, SECRET_KEY)
                .compact();
       return token;
    }

    public String getUsernameFromToken(String token){
        Claims claims = Jwts.parser()
                .setSigningKey(SECRET_KEY)
                .parseClaimsJws(token).getBody();
        return claims.getSubject();
    }


}
