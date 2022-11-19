package com.esl.springbootlogin.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.esl.springbootlogin.model.ERole;
import com.esl.springbootlogin.model.Role;

public interface RoleRepository extends JpaRepository<Role,Long> {
    Optional<Role> findByName(ERole name);
}
