package de.innologic.auth.domain.repository;

import de.innologic.auth.domain.entity.RegistrationProcess;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RegistrationProcessRepository extends JpaRepository<RegistrationProcess, Long> {
    Optional<RegistrationProcess> findByRegistrationId(String registrationId);
}
