package de.innologic.auth.domain.repository;

import de.innologic.auth.domain.entity.MfaRecoveryToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MfaRecoveryTokenRepository extends JpaRepository<MfaRecoveryToken, Long> {
    Optional<MfaRecoveryToken> findByTokenHash(String tokenHash);
}
