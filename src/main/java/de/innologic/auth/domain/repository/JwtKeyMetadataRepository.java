package de.innologic.auth.domain.repository;

import de.innologic.auth.domain.entity.JwtKeyMetadata;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface JwtKeyMetadataRepository extends JpaRepository<JwtKeyMetadata, Long> {
    Optional<JwtKeyMetadata> findByKid(String kid);
}
