package co.edu.uptc.auth.token;

import co.edu.uptc.auth.config.AuthProperties;
import co.edu.uptc.auth.user.UserResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

/** Emite los JWT (HS256) que el Gateway valida en cada petición a /api/**. */
@Service
public class TokenService {

    public static final String ROLE_CLAIM = "role";
    /** Id del estudiante vinculado al usuario; el frontend y el Gateway lo leen del token. */
    public static final String ESTUDIANTE_ID_CLAIM = "estudianteId";

    private final JwtEncoder encoder;
    private final AuthProperties.Jwt jwt;

    public TokenService(JwtEncoder encoder, AuthProperties props) {
        this.encoder = encoder;
        this.jwt = props.jwt();
    }

    public TokenResponse issue(UserResponse user) {
        Instant now = Instant.now();
        Duration ttl = jwt.expiresIn();
        JwtClaimsSet.Builder builder = JwtClaimsSet.builder()
                .issuer(jwt.issuer())
                .subject(user.username())
                .audience(List.of(jwt.audience()))
                .issuedAt(now)
                .expiresAt(now.plus(ttl))
                .claim(ROLE_CLAIM, user.role());
        if (user.estudianteId() != null) {
            builder.claim(ESTUDIANTE_ID_CLAIM, user.estudianteId());
        }
        JwtClaimsSet claims = builder.build();
        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        String token = encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
        return new TokenResponse(token, "Bearer", ttl.toSeconds(), user);
    }
}
