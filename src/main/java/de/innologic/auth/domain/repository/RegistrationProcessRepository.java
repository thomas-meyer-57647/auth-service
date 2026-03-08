package de.innologic.auth.domain.repository;

import de.innologic.auth.domain.entity.RegistrationProcess;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RegistrationProcessRepository extends JpaRepository<RegistrationProcess, Long> {
    Optional<RegistrationProcess> findByRegistrationId(String registrationId);

    long countByTenantId(String tenantId);

    long countByTenantIdAndStatus(String tenantId, String status);

    Optional<RegistrationProcess> findFirstByTenantIdOrderByModifiedAtDesc(String tenantId);
}
