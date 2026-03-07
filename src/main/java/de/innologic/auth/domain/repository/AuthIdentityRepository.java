package de.innologic.auth.domain.repository;

import de.innologic.auth.domain.entity.AuthIdentity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthIdentityRepository extends JpaRepository<AuthIdentity, Long> {
}
