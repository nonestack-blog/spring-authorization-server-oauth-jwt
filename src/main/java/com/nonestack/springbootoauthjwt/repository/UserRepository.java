package com.nonestack.springbootoauthjwt.repository;

import com.nonestack.springbootoauthjwt.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository  extends JpaRepository<User, Long> {

    @Query("select u from User u where u.email = :email and u.active = true")
    Optional<User> findOneByEmailAndActive(String email);

}
