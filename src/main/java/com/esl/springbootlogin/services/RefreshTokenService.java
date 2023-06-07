package com.esl.springbootlogin.services;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.esl.springbootlogin.payload.jwt.RefreshToken;
import com.esl.springbootlogin.repository.RefreshTokenRepository;
import com.esl.springbootlogin.repository.UserRepository;
import com.esl.springbootlogin.security.jwt.exception.TokenRefreshException;

/* service which uses RefreshTokenRepository above 
for providing several useful methods:

findByToken(): Find a RefreshToken based on the natural 
id i.e the token itself
createRefreshToken(): Create and return a new Refresh Token
verifyExpiration(): Verify whether the token provided 
has expired or not. If the token was expired, 
delete it from database and throw TokenRefreshException */
@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    @Value("${esl.app.jwtRefreshExpirationMs}")
    private Long refreshTokenDurationMs;

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    public RefreshToken createRefreshToken(Long userId) {

        RefreshToken refreshToken = new RefreshToken();

        refreshToken.setUser(
                userRepository.findById(userId).orElseThrow(() -> new RuntimeException("Usuário não encontrado")));

        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
        refreshToken.setToken(UUID.randomUUID().toString());

        refreshToken = refreshTokenRepository.save(refreshToken);
        return refreshToken;
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            throw new TokenRefreshException(token.getToken(),
                    "Refresh token was expired. Please make a new signin request");
        }

        return token;
    }

    @Transactional
    public int deleteByUserId(Long userId) {
        return refreshTokenRepository.deleteByUser(
                userRepository.findById(userId).orElseThrow(() -> new RuntimeException("Usuário não encontrado")));
    }
}
