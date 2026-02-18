package de.innologic.auth.domain.repository;

import de.innologic.auth.domain.entity.Mfa;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MfaRepository extends JpaRepository<Mfa, Long> {
    Optional<Mfa> findByCredentialId(Long credentialId);
}
