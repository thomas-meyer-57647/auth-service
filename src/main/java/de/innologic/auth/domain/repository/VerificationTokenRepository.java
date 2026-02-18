package de.innologic.auth.domain.repository;

import de.innologic.auth.domain.entity.VerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;

public interface VerificationTokenRepository extends JpaRepository<VerificationToken, Long> {
    long deleteByExpiresAtBefore(Instant before);
}
