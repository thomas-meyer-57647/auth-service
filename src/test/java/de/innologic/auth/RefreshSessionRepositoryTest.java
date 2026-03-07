package de.innologic.auth;

import de.innologic.auth.domain.entity.AuthCredential;
import de.innologic.auth.domain.entity.RefreshSession;
import de.innologic.auth.domain.enums.SessionPolicy;
import de.innologic.auth.domain.enums.UserStatus;
import de.innologic.auth.domain.repository.CredentialRepository;
import de.innologic.auth.domain.repository.RefreshSessionRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.dao.DataIntegrityViolationException;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DataJpaTest
class RefreshSessionRepositoryTest {

    @Autowired
    private RefreshSessionRepository sessionRepository;

    @Autowired
    private CredentialRepository credentialRepository;

    @Test
    void storesAndRetrievesSession() {
        AuthCredential credential = createCredential("session@example.com");
        RefreshSession session = new RefreshSession();
        session.setCredential(credential);
        session.setSid("sid-123");
        session.setSessionPolicy(SessionPolicy.HOURS_24);
        session.setRefreshTokenHash("hash-123");
        session.setCreatedAt(Instant.now());
        session.setUpdatedAt(Instant.now());
        session.setExpiresAt(Instant.now().plusSeconds(3600));
        sessionRepository.save(session);

        Optional<RefreshSession> stored = sessionRepository.findBySid("sid-123");
        assertThat(stored).isPresent()
                .get()
                .extracting(RefreshSession::getRefreshTokenHash)
                .isEqualTo("hash-123");
    }

    @Test
    void duplicateSidIsRejected() {
        AuthCredential credential = createCredential("sessions@example.com");
        RefreshSession first = buildSession(credential, "sid-dup");
        sessionRepository.save(first);

        RefreshSession second = buildSession(credential, "sid-dup");
        assertThatThrownBy(() -> sessionRepository.saveAndFlush(second))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    private RefreshSession buildSession(AuthCredential credential, String sid) {
        RefreshSession session = new RefreshSession();
        session.setCredential(credential);
        session.setSid(sid);
        session.setSessionPolicy(SessionPolicy.HOURS_24);
        session.setRefreshTokenHash("hash-" + sid);
        session.setCreatedAt(Instant.now());
        session.setUpdatedAt(Instant.now());
        session.setExpiresAt(Instant.now().plusSeconds(3600));
        return session;
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
