package de.innologic.auth.domain.repository;

import de.innologic.auth.domain.entity.Credential;
import de.innologic.auth.domain.enums.UserStatus;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.Collection;
import java.util.Optional;

public interface CredentialRepository extends JpaRepository<Credential, Long> {
    Optional<Credential> findByEmail(String email);

    long deleteByUserStatusInAndCreatedAtBefore(Collection<UserStatus> statuses, Instant before);
}
