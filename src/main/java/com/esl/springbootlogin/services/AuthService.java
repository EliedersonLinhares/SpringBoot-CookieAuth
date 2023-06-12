package com.esl.springbootlogin.services;

import java.util.Calendar;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.esl.springbootlogin.dto.auth.request.SignupRequestRecord;
import com.esl.springbootlogin.dto.auth.response.UserInfoResponse;
import com.esl.springbootlogin.event.RegistrationCompleteEvent;
import com.esl.springbootlogin.model.ERole;
import com.esl.springbootlogin.model.Role;
import com.esl.springbootlogin.model.User;
import com.esl.springbootlogin.model.token.VerificationToken;
import com.esl.springbootlogin.repository.RoleRepository;
import com.esl.springbootlogin.repository.UserRepository;
import com.esl.springbootlogin.repository.VerificationTokenRepository;
import com.esl.springbootlogin.security.services.UserDetailsImpl;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder encoder;
    private final RefreshTokenService refreshTokenService;
    private final ApplicationEventPublisher publisher;
    private final VerificationTokenRepository verificationTokenRepository;

    public void register(SignupRequestRecord signUpRequest, final HttpServletRequest request) {

        // Create new user's account
        User user = new User(signUpRequest.username(),
                signUpRequest.email(),
                encoder.encode(signUpRequest.password()));

        Set<String> strRoles = signUpRequest.role();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN_OWNER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);

                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);

                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }
        publisher.publishEvent(new RegistrationCompleteEvent(user, applicationUrl(request)));

        user.setRoles(roles);
        userRepository.save(user);
    }

    public String applicationUrl(HttpServletRequest request) {
        return "http://" + request.getServerName() + ":" + request.getServerPort() + request.getContextPath();
    }

    public Set<Role> extracted(SignupRequestRecord signUpRequest) {
        Set<String> strRoles = signUpRequest.role();
        Set<Role> roles = new HashSet<>();

        if (Objects.isNull(strRoles)) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Tipo de permissão não encontrado"));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                if (role.equals("admin")) {
                    Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN_OWNER).get();
                    roles.add(adminRole);
                }
                if (role.equals("mod")) {
                    Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR).get();
                    roles.add(modRole);
                }

            });
        }
        return roles;
    }

    public void register2(User user) {
        userRepository.save(
                new User(user.getUsername(),
                        user.getEmail(),
                        encoder.encode(user.getPassword())));
    }

    public User convertDtotoEntity(SignupRequestRecord signupRequest) {
        User user = new User();
        user.setUsername(signupRequest.username());
        user.setEmail(signupRequest.email());
        user.setPassword(signupRequest.password());
        return user;
    }

    public void logout() {
        Object principle = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (!"anonymousUser".equals(principle.toString())) {
            Long userId = ((UserDetailsImpl) principle).getId();
            refreshTokenService.deleteByUserId(userId);
        }

    }

    public boolean duplicateUser(SignupRequestRecord signUpRequest) {
        return userRepository.existsByUsername(signUpRequest.username());
    }

    public boolean duplicateEmail(SignupRequestRecord signUpRequest) {
        return userRepository.existsByEmail(signUpRequest.email());
    }

    public UserInfoResponse convertEntityToDto(User user) {
        // List<String> roleList = new ArrayList<>(user.getRoles().toString());

        List<GrantedAuthority> authorities = user.getRoles()
                .stream().map(role -> new SimpleGrantedAuthority(role.getName().name()))
                .collect(Collectors.toList());

        UserInfoResponse userInfoResponse = new UserInfoResponse();
        userInfoResponse.setId(user.getId());
        userInfoResponse.setUsername(user.getUsername());
        userInfoResponse.setEmail(user.getEmail());
        userInfoResponse.setRoles(
                authorities
                        .stream()
                        .map(object -> Objects.toString(object, null))
                        .collect(Collectors.toList()));

        return userInfoResponse;
    }

    public List<UserInfoResponse> getAllUsersService() {
        return userRepository.findAll()
                .stream()
                .map(this::convertEntityToDto)
                .collect(Collectors.toList());

    }

    public Object getUserAuthenticated(Authentication authentication) {
        try {
            return authentication.getPrincipal();
        } catch (Exception e) {
            return null;
        }
    }

    public void saveUserVerificationToken(User theUser, String token) {
        var verificationToken = new VerificationToken(token, theUser);
        verificationTokenRepository.save(verificationToken);
    }

    public String validateToken(String verificationToken) {
        VerificationToken token = verificationTokenRepository.findByToken(verificationToken);
        if (token == null) {
            return "invalid";
        }
        if (token.getUser().isEnabled()) {
            return "enabled";
        }

        User user = token.getUser();
        Calendar calendar = Calendar.getInstance();
        if ((token.getExpirationTime().getTime() - calendar.getTime().getTime()) <= 0) {
            verificationTokenRepository.delete(token);
            return "expired";
        }
        // verificationTokenRepository.delete(token);
        user.setEnabled(true);
        userRepository.save(user);

        return "valid";
    }

}
