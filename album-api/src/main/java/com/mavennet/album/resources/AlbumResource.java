package com.mavennet.album.resources;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import com.mavennet.album.entity.Album;
import com.mavennet.album.entity.Photo;
import com.mavennet.album.entity.User;
import com.mavennet.album.service.AlbumService;
import com.mavennet.album.service.PhotoService;
import com.mavennet.album.service.UserService;

@RestController
public class AlbumResource {
	
	@Autowired
	UserService userService;
	
	@Autowired
	AlbumService albumService;
	
	@Autowired
	PhotoService photoService;

	@GetMapping("/users")
	public List<User> fetchAllUsers() {
		return userService.fetchAllUsers();
	}
	
	@GetMapping("/albums")
	public List<Album> fetchAlbumsByUserId(){
		return albumService.fechAlbumsByUserId();
	}
	
	@GetMapping("/albums/{albumId}")
	public Optional<Album> fetchAlbumById(@PathVariable (value="albumId") Long albumId){
		return albumService.fetchAlbumById(albumId);
	}
	
	@GetMapping("/photos")
	public List<Photo> fetchPhotosByUserId(){
		return photoService.fetchPhotosByUserId();
	}
	
	
	@GetMapping("photos/{photoId}")
	public Optional<Photo> fetchPhotoById(@PathVariable (value="photoId") Long id){
		return photoService.fetchPhotoById(id);
	}
}