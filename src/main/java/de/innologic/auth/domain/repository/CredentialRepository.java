package de.innologic.auth.domain.repository;

import de.innologic.auth.domain.entity.AuthCredential;
import de.innologic.auth.domain.enums.UserStatus;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.Collection;
import java.util.Optional;

public interface CredentialRepository extends JpaRepository<AuthCredential, Long> {
    Optional<AuthCredential> findByLoginEmail(String loginEmail);

    long deleteByStatusInAndCreatedAtBefore(Collection<UserStatus> statuses, Instant before);
}
