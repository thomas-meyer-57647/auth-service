package de.innologic.auth;

import de.innologic.auth.domain.entity.JwtKeyMetadata;
import de.innologic.auth.domain.repository.JwtKeyMetadataRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.dao.DataIntegrityViolationException;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DataJpaTest
class JwtKeyMetadataRepositoryTest {

    @Autowired
    private JwtKeyMetadataRepository repository;

    @Test
    void storesAndLoadsMetadataByKid() {
        JwtKeyMetadata metadata = new JwtKeyMetadata();
        metadata.setKid("kid-1");
        metadata.setAlgorithm("RS256");
        metadata.setPublicKey("public");
        metadata.setPrivateKeyRef("private-ref");
        metadata.setStatus("ACTIVE");
        metadata.setCreatedAt(Instant.now());
        metadata.setValidFrom(Instant.now());
        metadata.setValidUntil(Instant.now().plusSeconds(3600));
        repository.save(metadata);

        assertThat(repository.findByKid("kid-1")).isPresent()
                .get()
                .extracting(JwtKeyMetadata::getAlgorithm)
                .isEqualTo("RS256");
    }

    @Test
    void duplicateKidIsRejected() {
        JwtKeyMetadata existing = new JwtKeyMetadata();
        existing.setKid("kid-dup");
        existing.setAlgorithm("RS256");
        existing.setPublicKey("public");
        existing.setStatus("ACTIVE");
        existing.setCreatedAt(Instant.now());
        existing.setValidFrom(Instant.now());
        existing.setValidUntil(Instant.now().plusSeconds(3600));
        repository.save(existing);

        JwtKeyMetadata duplicate = new JwtKeyMetadata();
        duplicate.setKid("kid-dup");
        duplicate.setAlgorithm("RS256");
        duplicate.setPublicKey("public");
        duplicate.setStatus("ACTIVE");
        duplicate.setCreatedAt(Instant.now());
        duplicate.setValidFrom(Instant.now());
        duplicate.setValidUntil(Instant.now().plusSeconds(3600));

        assertThatThrownBy(() -> repository.saveAndFlush(duplicate))
                .isInstanceOf(DataIntegrityViolationException.class);
    }
}
