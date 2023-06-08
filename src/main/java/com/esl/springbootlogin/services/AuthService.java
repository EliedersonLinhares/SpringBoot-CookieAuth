package com.esl.springbootlogin.services;

import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.esl.springbootlogin.dto.auth.request.SignupRequestRecord;
import com.esl.springbootlogin.dto.auth.response.UserInfoResponse;
import com.esl.springbootlogin.model.ERole;
import com.esl.springbootlogin.model.Role;
import com.esl.springbootlogin.model.User;
import com.esl.springbootlogin.repository.RoleRepository;
import com.esl.springbootlogin.repository.UserRepository;
import com.esl.springbootlogin.security.services.UserDetailsImpl;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder encoder;
    private final RefreshTokenService refreshTokenService;

    public void register(SignupRequestRecord signUpRequest) {

        // Create new user's account
        User user = new User(signUpRequest.username(),
                signUpRequest.email(),
                encoder.encode(signUpRequest.password()));

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

        user.setRoles(roles);
        userRepository.save(user);
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

}
