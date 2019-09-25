package com.mavennet.album.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.mavennet.album.entity.Photo;

public interface PhotoRepository extends JpaRepository<Photo, Long> {
	
	List<Photo> findByAlbumId(Long albumId);
	
	@Query(value="SELECT P.ID,P.TITLE,P.THUMBNAIL_URL,P.URL,P.ALBUM_ID FROM PHOTO P,ALBUM A WHERE P.ALBUM_ID=A.ID AND A.USER_ID=:userId",nativeQuery=true)
	List<Photo> findPhotosByUserId(@Param("userId") Long userId);
	
}