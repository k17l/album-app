package com.mavennet.album.service;

import java.util.List;
import java.util.Optional;

import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.mavennet.album.entity.Album;
import com.mavennet.album.repository.AlbumRepository;
import com.mavennet.album.repository.UserRepository;
import com.mavennet.album.util.AppUtils;

@Service
public class AlbumService {
	
	@Autowired
	AlbumRepository albumRepository;
	
	@Autowired
	UserRepository userRepository;

	@Transactional
	public List<Album> fechAlbumsByUserId(){
		return albumRepository.findByUserId(AppUtils.getLoggedInUserId());
	}
	
	public Optional<Album> fetchAlbumById(Long albumId){
		return albumRepository.findById(albumId);
	}
}