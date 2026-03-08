package de.innologic.auth.domain.repository;

import de.innologic.auth.domain.entity.AuthIdentity;
import de.innologic.auth.domain.enums.Provider;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AuthIdentityRepository extends JpaRepository<AuthIdentity, Long> {

    Optional<AuthIdentity> findByProviderAndProviderSubject(Provider provider, String providerSubject);
}
