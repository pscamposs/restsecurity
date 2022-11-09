package me.patrick.restsecurity.repository;

import me.patrick.restsecurity.model.UserModel;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface UserRepository extends JpaRepository<UserModel, Integer> {
    @Query("SELECT e FROM UserModel e JOIN FETCH e.roles WHERE e.username= (:username)")
    public UserModel findByUsername(@Param("username") String username);
}