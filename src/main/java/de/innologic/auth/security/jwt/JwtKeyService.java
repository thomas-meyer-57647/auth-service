package de.innologic.auth.security.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Service
public class JwtKeyService {

    private final String keyId;
    private RSAKey rsaKey;

    public JwtKeyService(@Value("${auth.jwt.kid:dev-rsa-key-1}") String keyId) {
        this.keyId = keyId;
    }

    @PostConstruct
    public void init() {
        this.rsaKey = generateDevRsaKey();
    }

    public String getKeyId() {
        return keyId;
    }

    public JWKSet getPublicJwkSet() {
        return new JWKSet(rsaKey.toPublicJWK());
    }

    public RSAPrivateKey getPrivateKey() {
        try {
            return rsaKey.toRSAPrivateKey();
        } catch (JOSEException e) {
            throw new IllegalStateException("Unable to extract RSA private key", e);
        }
    }

    public RSAPublicKey getPublicKey() {
        try {
            return rsaKey.toRSAPublicKey();
        } catch (JOSEException e) {
            throw new IllegalStateException("Unable to extract RSA public key", e);
        }
    }

    private RSAKey generateDevRsaKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                    .privateKey((RSAPrivateKey) keyPair.getPrivate())
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.RS256)
                    .keyID(keyId)
                    .build();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Unable to generate RSA keypair for JWT", e);
        }
    }
}
