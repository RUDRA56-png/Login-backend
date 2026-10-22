package com.example.auth.repository;

import com.example.auth.entity.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.util.Optional;

public interface UserSessionRepository extends JpaRepository<UserSession, Long> {

    Optional<UserSession> findByTokenIdAndActiveTrue(String tokenId);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("update UserSession s set s.active = false where s.user.id = :userId and s.active = true")
    int deactivateAllByUserId(@Param("userId") Long userId);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("update UserSession s set s.active = false "
            + "where s.user.id = :userId and s.active = true and s.tokenId <> :tokenId")
    int deactivateOthers(@Param("userId") Long userId, @Param("tokenId") String tokenId);
}
