package de.innologic.auth;

import de.innologic.auth.domain.entity.RegistrationProcess;
import de.innologic.auth.domain.repository.RegistrationProcessRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.dao.DataIntegrityViolationException;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DataJpaTest
class RegistrationProcessRepositoryTest {

    @Autowired
    private RegistrationProcessRepository repository;

    @Test
    void canStoreAndRetrieveProcess() {
        RegistrationProcess process = new RegistrationProcess();
        process.setRegistrationId("reg-123");
        process.setTenantId("tenant-1");
        process.setUserId("user-1");
        process.setStatus("PENDING");
        process.setExpiresAt(Instant.now().plusSeconds(600));
        process.setCreatedAt(Instant.now());
        process.setModifiedAt(Instant.now());
        repository.save(process);

        assertThat(repository.findByRegistrationId("reg-123")).isPresent()
                .get()
                .extracting(RegistrationProcess::getStatus)
                .isEqualTo("PENDING");
    }

    @Test
    void duplicateRegistrationIdIsRejected() {
        RegistrationProcess first = new RegistrationProcess();
        first.setRegistrationId("reg-dup");
        first.setTenantId("tenant");
        first.setUserId("user-a");
        first.setStatus("PENDING");
        first.setExpiresAt(Instant.now().plusSeconds(600));
        first.setCreatedAt(Instant.now());
        first.setModifiedAt(Instant.now());
        repository.save(first);

        RegistrationProcess duplicate = new RegistrationProcess();
        duplicate.setRegistrationId("reg-dup");
        duplicate.setTenantId("tenant-dup");
        duplicate.setUserId("user-b");
        duplicate.setStatus("PENDING");
        duplicate.setExpiresAt(Instant.now().plusSeconds(600));
        duplicate.setCreatedAt(Instant.now());
        duplicate.setModifiedAt(Instant.now());

        assertThatThrownBy(() -> repository.saveAndFlush(duplicate))
                .isInstanceOf(DataIntegrityViolationException.class);
    }
}
