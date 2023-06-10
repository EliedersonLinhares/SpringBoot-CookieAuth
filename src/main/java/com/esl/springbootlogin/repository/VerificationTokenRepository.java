package com.esl.springbootlogin.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.esl.springbootlogin.model.token.VerificationToken;

public interface VerificationTokenRepository extends JpaRepository<VerificationToken, Long> {

    VerificationToken findByToken(String token);
}
