package com.w3auth.backend.infrastructure;

import com.w3auth.backend.session.JwtPolicy;
import com.w3auth.backend.session.JwtService;
import io.jsonwebtoken.security.Keys;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;
import java.util.Base64;

@Configuration
@EnableConfigurationProperties(JwtProperties.class)
class JwtConfiguration {

    @Bean
    JwtPolicy jwtPolicy(JwtProperties properties) {
        byte[] keyBytes = Base64.getDecoder().decode(properties.secret());
        if (keyBytes.length < 32) {
            throw new IllegalStateException(
                    "walletauth.jwt.secret must be at least 256 bits (32 bytes base64-encoded); " +
                    "got " + keyBytes.length + " bytes");
        }
        SecretKey key = Keys.hmacShaKeyFor(keyBytes);
        return new JwtPolicy(key, properties.ttl(), properties.audience());
    }

    @Bean
    JwtService jwtService(JwtPolicy jwtPolicy) {
        return new JwtService(jwtPolicy);
    }
}
