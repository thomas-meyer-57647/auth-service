package de.innologic.auth.domain.repository;

import de.innologic.auth.domain.entity.Identity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IdentityRepository extends JpaRepository<Identity, Long> {
}
