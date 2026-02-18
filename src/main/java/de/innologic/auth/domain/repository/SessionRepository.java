package de.innologic.auth.domain.repository;

import de.innologic.auth.domain.entity.Session;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface SessionRepository extends JpaRepository<Session, Long> {
    Optional<Session> findByRefreshTokenHash(String refreshTokenHash);

    List<Session> findAllByCredentialIdAndRevokedAtIsNull(Long credentialId);
}
