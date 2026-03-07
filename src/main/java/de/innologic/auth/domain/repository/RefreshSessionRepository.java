package de.innologic.auth.domain.repository;

import de.innologic.auth.domain.entity.RefreshSession;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface RefreshSessionRepository extends JpaRepository<RefreshSession, Long> {
    Optional<RefreshSession> findByRefreshTokenHash(String refreshTokenHash);
    Optional<RefreshSession> findBySid(String sid);

    List<RefreshSession> findAllByCredentialIdAndRevokedAtIsNull(Long credentialId);
}
