package com.esl.springbootlogin.security.jwt;

import java.util.Date;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import com.esl.springbootlogin.model.User;
import com.esl.springbootlogin.security.services.UserDetailsImpl;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

/**
 *
 * Essa classe tem três funções principais:
 * getJwtFromCookies: pega token JWT a partir dos Cookies pelo nome do Cookie
 * generateJwtCookie: cria um Cookie contendo um token JWT com username, data,
 * expiração, secret
 * getCleanJwtCookie: retorna um Cookie com valor null (usado para limpar o
 * cookie)
 * getUserNameFromJwtToken: obtem um username a partir de um token JWT
 * validateJwtToken: valida um token JWT contra o secret
 */
@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${esl.app.jwtSecret}")
    private String jwtSecret;

    @Value("${esl.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    @Value("${esl.app.jwtRefreshCookieName}")
    private String jwtRefreshCookie;

    @Value("${esl.app.jwtCookieName}")
    private String jwtCookie;

    /*
     * public ResponseCookie generateJwtCookie(UserDetailsImpl userPrincipal) {
     * String jwt = generateTokenFromUsername(userPrincipal.getUsername());
     * return generateCookie(jwtCookie, jwt, "/api");
     * }
     * 
     * public ResponseCookie generateJwtCookie(User user) {
     * String jwt = generateTokenFromUsername(user.getUsername());
     * return generateCookie(jwtCookie, jwt, "/api");
     * }
     */
    public ResponseCookie generateJwtCookie(UserDetailsImpl userPrincipal) {
        String jwt = generateTokenFromUsername(userPrincipal.getEmail());
        return generateCookie(jwtCookie, jwt, "/api");
    }

    public ResponseCookie generateJwtCookie(User user) {
        String jwt = generateTokenFromUsername(user.getEmail());
        return generateCookie(jwtCookie, jwt, "/api");
    }

    public ResponseCookie generateRefreshJwtCookie(String refreshToken) {
        return generateCookie(jwtRefreshCookie, refreshToken, "/api/auth/refreshtoken");
    }

    public String getJwtFromCookies(HttpServletRequest request) {
        return getCookieValueByName(request, jwtCookie);
    }

    public String getJwtRefreshFromCookies(HttpServletRequest request) {
        return getCookieValueByName(request, jwtRefreshCookie);
    }

    public ResponseCookie getCleanJwtCookie(String value) {
        return ResponseCookie.from(jwtCookie, value).path("/api").build();
    }

    public ResponseCookie getCleanJwtRefreshCookie(String value) {
        return ResponseCookie.from(jwtRefreshCookie, value).path("/api/auth/refreshtoken").build();
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }

    public String generateTokenFromUsername(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    private ResponseCookie generateCookie(String name, String value, String path) {
        return ResponseCookie.from(name, value).path(path).maxAge(24 * 60 * 60).httpOnly(true).build();
    }

    private String getCookieValueByName(HttpServletRequest request, String name) {
        Cookie cookie = WebUtils.getCookie(request, name);
        if (cookie != null) {
            return cookie.getValue();
        } else {
            return null;
        }
    }
}
