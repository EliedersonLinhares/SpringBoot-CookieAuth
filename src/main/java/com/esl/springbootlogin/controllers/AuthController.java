package com.esl.springbootlogin.controllers;

import java.io.UnsupportedEncodingException;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.esl.springbootlogin.dto.auth.request.LoginRequestRecord;
import com.esl.springbootlogin.dto.auth.request.SignupRequestRecord;
import com.esl.springbootlogin.dto.auth.response.MessageResponseRecord;
import com.esl.springbootlogin.dto.auth.response.UserInfoResponse;
import com.esl.springbootlogin.event.RegistrationCompleteEventListener;
import com.esl.springbootlogin.model.jwt.RefreshToken;
import com.esl.springbootlogin.model.token.VerificationToken;
import com.esl.springbootlogin.security.jwt.JwtUtils;
import com.esl.springbootlogin.security.jwt.exception.refreshtoken.TokenRefreshException;
import com.esl.springbootlogin.security.services.UserDetailsImpl;
import com.esl.springbootlogin.services.AuthService;
import com.esl.springbootlogin.services.LoggedInUser;
import com.esl.springbootlogin.services.RefreshTokenService;

import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

//@CrossOrigin(origins = "*", maxAge = 3600)
@CrossOrigin(origins = "http://localhost:4200", maxAge = 3600, allowCredentials = "true")
// @CrossOrigin("http://localhost:4200")
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;
    private final AuthService authservice;
    private final RegistrationCompleteEventListener eventListener;
    private final HttpServletRequest servletRequest;

    @PostMapping("/signin")
    public ResponseEntity<Object> authenticateUser(@Valid @RequestBody LoginRequestRecord loginRequest) {

        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.email(),
                        loginRequest.password()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());

        ResponseCookie jwtRefreshCookie = jwtUtils.generateRefreshJwtCookie(refreshToken.getToken());

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                .header(HttpHeaders.SET_COOKIE, jwtRefreshCookie.toString())
                .body("Usuário logado com sucesso!");
    }

    @PostMapping("/signup")
    public ResponseEntity<Object> registerUser(@Valid @RequestBody SignupRequestRecord signUpRequest,
            final HttpServletRequest request) {
        if (authservice.duplicateUser(signUpRequest)) {
            return ResponseEntity.ok().body(new MessageResponseRecord("Erro: Nome de usuario já cadastrado!"));
        }
        if (authservice.duplicateEmail(signUpRequest)) {
            return ResponseEntity.ok().body(new MessageResponseRecord("Erro: Email já cadastrado!"));
        }
        authservice.register(signUpRequest, request);
        return ResponseEntity.ok().body("usuario cadastrado com sucesso! Acesse seu email para confirmar o cadastro.");
    }

    @PostMapping("/signout")
    public ResponseEntity<Object> logoutUser() {
        authservice.logout();

        ResponseCookie jwtCookie = jwtUtils.getCleanJwtCookie(null);
        ResponseCookie jwtRefreshCookie = jwtUtils.getCleanJwtRefreshCookie(null);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                .header(HttpHeaders.SET_COOKIE, jwtRefreshCookie.toString())
                .body(new MessageResponseRecord("Usuário deslogado com sucesso!"));
    }

    @GetMapping("/refreshtoken")
    public ResponseEntity<MessageResponseRecord> refreshtoken(HttpServletRequest request) {
        String refreshToken = jwtUtils.getJwtRefreshFromCookies(request);

        if ((refreshToken != null) && (refreshToken.length() > 0)) {
            return refreshTokenService.findByToken(refreshToken)
                    .map(refreshTokenService::verifyExpiration)
                    .map(RefreshToken::getUser)
                    .map(user -> {
                        ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(user);

                        return ResponseEntity.ok()
                                .header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                                .header(HttpHeaders.SET_COOKIE, refreshToken)
                                .body(new MessageResponseRecord("Token atualizado com sucesso!"));
                    })
                    .orElseThrow(() -> new TokenRefreshException(refreshToken,
                            "token não consta na base de dados!"));
        }

        return ResponseEntity.badRequest().body(new MessageResponseRecord("Token atualiado está vazio!"));
    }

    @GetMapping("/users")
    @PreAuthorize("hasRole('MODERATOR') or hasRole('ADMIN_OWNER')")
    public ResponseEntity<List<UserInfoResponse>> getAllUsers() {
        try {
            List<UserInfoResponse> userInfoResponses = authservice.getAllUsersService();
            if (userInfoResponses.isEmpty()) {
                return new ResponseEntity<>(HttpStatus.NO_CONTENT);
            }

            return new ResponseEntity<>(userInfoResponses, HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/user-profile")
    public ResponseEntity<Object> getUserAuthenticate(@LoggedInUser UserDetailsImpl userDetailsImpl) {
        try {
            List<String> roles = userDetailsImpl.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());

            return ResponseEntity.ok().body(new UserInfoResponse(userDetailsImpl.getId(),
                    userDetailsImpl.getUsername(),
                    userDetailsImpl.getEmail(),
                    roles));
        } catch (Exception e) {
            return new ResponseEntity<>("Sem usuario autenticado", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/verifyemail")
    public ResponseEntity<Object> verifyemail(@RequestParam("token") String token) {

        String url = authservice.applicationUrl(servletRequest) + "/api/auth/resend-verificationtoken?token=" + token;

        String verificationResult = authservice.validateToken(token);
        if (verificationResult.equalsIgnoreCase("invalid")) {
            return ResponseEntity.ok().body("token inválido.");
        }
        if (verificationResult.equalsIgnoreCase("enabled")) {
            return ResponseEntity.ok().body("Conta já confirmada,por favor, faça o login");
        }
        if (verificationResult.equalsIgnoreCase("expired")) {
            return ResponseEntity.ok().body(
                    "Tempo de confirmação expirado,<a href=\"" + url
                            + "\">Clique aqui! E obtenha um novo lik de confirmação.</a>");
        }

        return ResponseEntity.ok().body("Email verificado com sucesso, faça o login");

    }

    @GetMapping("/resend-verificationtoken")
    public ResponseEntity<Object> resendVerificationToken(@RequestParam("token") String oldToken,
            final HttpServletRequest request) throws UnsupportedEncodingException, MessagingException {
        VerificationToken verificationToken = authservice.generateNewVerificationToken(oldToken);
        resendVerificationTokenEmail(authservice.applicationUrl(request), verificationToken);
        return ResponseEntity.ok().body("Novo link enviado para seu email, por favor, confirme para ativar sua conta");
    }

    private void resendVerificationTokenEmail(String applicationUrl, VerificationToken verificationToken)
            throws UnsupportedEncodingException, MessagingException {

        String url = applicationUrl + "/api/auth/verifyemail?token=" + verificationToken.getToken();
        eventListener.sendVerificationEmail(url);
        log.info("Url example: {}", url);
    }
}
