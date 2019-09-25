package com.mavennet.album.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.mavennet.album.entity.Album;

public interface AlbumRepository extends JpaRepository<Album, Long> {

	List<Album> findByUserId(Long userId);
	
}