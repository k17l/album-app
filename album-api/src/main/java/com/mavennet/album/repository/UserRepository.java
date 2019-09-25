package com.mavennet.album.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.mavennet.album.entity.User;

public interface UserRepository extends JpaRepository<User, Long>{

	Optional<User> findByUsername(String username);
	
}