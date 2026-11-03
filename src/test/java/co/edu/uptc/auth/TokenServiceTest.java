package co.edu.uptc.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.uptc.auth.config.AuthProperties;
import co.edu.uptc.auth.token.TokenResponse;
import co.edu.uptc.auth.token.TokenService;
import co.edu.uptc.auth.user.UserResponse;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

/** Prueba unitaria (sin Spring ni base de datos): el token emitido se puede verificar con la misma clave. */
class TokenServiceTest {

    private static final String SECRET = "0123456789-0123456789-0123456789-0123";

    @Test
    void issuesSignedTokenWithRoleAndExpiry() {
        AuthProperties props = new AuthProperties(
                new AuthProperties.Jwt(SECRET, Duration.ofHours(1), "api-gateway-uptc", "sistema-academico"),
                new AuthProperties.Admin("admin", "admin-password-1"));
        SecretKey key = new SecretKeySpec(SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        JWKSource<SecurityContext> jwks = new ImmutableSecret<>(key);
        TokenService service = new TokenService(new NimbusJwtEncoder(jwks), props);

        TokenResponse response = service.issue(new UserResponse("laura", "USER", 12L));

        Jwt jwt = NimbusJwtDecoder.withSecretKey(key).macAlgorithm(MacAlgorithm.HS256).build()
                .decode(response.accessToken());
        assertEquals("laura", jwt.getSubject());
        assertEquals("USER", jwt.getClaimAsString(TokenService.ROLE_CLAIM));
        assertEquals(12L, ((Number) jwt.getClaim(TokenService.ESTUDIANTE_ID_CLAIM)).longValue());
        assertEquals("api-gateway-uptc", jwt.getIssuer().toString());
        assertTrue(jwt.getAudience().contains("sistema-academico"));
        assertTrue(jwt.getExpiresAt().isAfter(Instant.now()));
        assertEquals(3600L, response.expiresIn());
    }
}
