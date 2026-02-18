package de.innologic.auth.web;

import de.innologic.auth.security.jwt.JwtKeyService;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class JwksController {

    private final JwtKeyService jwtKeyService;

    public JwksController(JwtKeyService jwtKeyService) {
        this.jwtKeyService = jwtKeyService;
    }

    @GetMapping(value = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> jwks() {
        return jwtKeyService.getPublicJwkSet().toJSONObject();
    }
}
