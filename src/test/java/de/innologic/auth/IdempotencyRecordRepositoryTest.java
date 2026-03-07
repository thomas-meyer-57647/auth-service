package de.innologic.auth;

import de.innologic.auth.domain.entity.IdempotencyRecord;
import de.innologic.auth.domain.repository.IdempotencyRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.dao.DataIntegrityViolationException;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DataJpaTest
class IdempotencyRecordRepositoryTest {

    @Autowired
    private IdempotencyRepository repository;

    @Test
    void storesRecordWithUniqueKey() {
        IdempotencyRecord record = new IdempotencyRecord();
        record.setIdempotencyKey("idem-123");
        record.setRequestHash("hash");
        record.setResponseStatus(200);
        record.setCreatedAt(Instant.now());
        record.setExpiresAt(Instant.now().plusSeconds(3600));
        repository.save(record);

        assertThat(repository.findByIdempotencyKey("idem-123")).isPresent();
    }

    @Test
    void duplicateKeyIsRejected() {
        IdempotencyRecord first = new IdempotencyRecord();
        first.setIdempotencyKey("idem-dup");
        first.setRequestHash("hash-a");
        first.setCreatedAt(Instant.now());
        first.setExpiresAt(Instant.now().plusSeconds(3600));
        repository.save(first);

        IdempotencyRecord second = new IdempotencyRecord();
        second.setIdempotencyKey("idem-dup");
        second.setRequestHash("hash-b");
        second.setCreatedAt(Instant.now());
        second.setExpiresAt(Instant.now().plusSeconds(3600));

        assertThatThrownBy(() -> repository.saveAndFlush(second))
                .isInstanceOf(DataIntegrityViolationException.class);
    }
}
