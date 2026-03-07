package de.innologic.auth;

import de.innologic.auth.domain.entity.AuthCredential;
import de.innologic.auth.domain.entity.AuthIdentity;
import de.innologic.auth.domain.enums.Provider;
import de.innologic.auth.domain.enums.UserStatus;
import de.innologic.auth.domain.repository.AuthIdentityRepository;
import de.innologic.auth.domain.repository.CredentialRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.dao.DataIntegrityViolationException;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DataJpaTest
class AuthIdentityRepositoryTest {

    @Autowired
    private AuthIdentityRepository repository;

    @Autowired
    private CredentialRepository credentialRepository;

    @Test
    void storesAndLoadsIdentity() {
        AuthCredential credential = createCredential("identity@example.com");
        AuthIdentity identity = new AuthIdentity();
        identity.setCredential(credential);
        identity.setProvider(Provider.GOOGLE);
        identity.setProviderSubject("google-123");
        identity.setProviderEmail("identity@example.com");
        identity.setCreatedAt(Instant.now());
        repository.save(identity);

        Optional<AuthIdentity> stored = repository.findById(identity.getId());
        assertThat(stored).isPresent()
                .get()
                .extracting(AuthIdentity::getProviderSubject)
                .isEqualTo("google-123");
    }

    @Test
    void duplicateProviderSubjectIsRejected() {
        AuthCredential credential = createCredential("dup@example.com");
        AuthIdentity first = new AuthIdentity();
        first.setCredential(credential);
        first.setProvider(Provider.FACEBOOK);
        first.setProviderSubject("dup-subject");
        first.setCreatedAt(Instant.now());
        repository.save(first);

        AuthIdentity duplicate = new AuthIdentity();
        duplicate.setCredential(credential);
        duplicate.setProvider(Provider.FACEBOOK);
        duplicate.setProviderSubject("dup-subject");
        duplicate.setCreatedAt(Instant.now());

        assertThatThrownBy(() -> repository.saveAndFlush(duplicate))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    private AuthCredential createCredential(String email) {
        AuthCredential credential = new AuthCredential();
        credential.setLoginEmail(email);
        credential.setPasswordHash("secret");
        credential.setCreatedAt(Instant.now());
        credential.setModifiedAt(Instant.now());
        credential.setEmailVerified(true);
        credential.setStatus(UserStatus.ACTIVE);
        credential.setFailedAttempts(0);
        return credentialRepository.save(credential);
    }
}
