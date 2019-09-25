package com.mavennet.album.service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.mavennet.album.entity.Photo;
import com.mavennet.album.repository.PhotoRepository;
import com.mavennet.album.util.AppUtils;

@Service
public class PhotoService {

	@Autowired
	PhotoRepository photoRepository;
	
	public List<Photo> fetchPhotosByUserId(){
		return photoRepository.findPhotosByUserId(AppUtils.getLoggedInUserId());
	}
	
	public Optional<Photo> fetchPhotoById(Long id){
		return photoRepository.findById(id);
	}
}