package co.edu.uptc.auth.config;

import co.edu.uptc.auth.error.JsonErrorWriter;
import co.edu.uptc.auth.token.TokenService;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.nio.charset.StandardCharsets;
import java.util.List;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;

/**
 * Este módulo FIRMA los tokens y además valida el JWT en sus propias rutas protegidas
 * (/api/auth/register y /api/auth/me), de modo que sigue siendo seguro aunque la plataforma lo exponga
 * públicamente. Solo el login y el health son públicos.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    static final String LOGIN_PATH = "/api/auth/login";

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JwtEncoder jwtEncoder(AuthProperties props) {
        JWKSource<SecurityContext> jwks = new ImmutableSecret<>(secretKey(props));
        return new NimbusJwtEncoder(jwks);
    }

    @Bean
    public JwtDecoder jwtDecoder(AuthProperties props) {
        AuthProperties.Jwt jwt = props.jwt();
        NimbusJwtDecoder decoder = NimbusJwtDecoder
                .withSecretKey(secretKey(props))
                .macAlgorithm(MacAlgorithm.HS256) // algoritmo fijo: evita "alg: none" y confusión HS/RS
                .build();
        OAuth2TokenValidator<Jwt> audience = new JwtClaimValidator<List<String>>(
                JwtClaimNames.AUD, aud -> aud != null && aud.contains(jwt.audience()));
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(jwt.issuer()), audience));
        return decoder;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtDecoder jwtDecoder) throws Exception {
        AuthenticationEntryPoint unauthorized = (request, response, ex) -> {
            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer realm=\"auth-service\"");
            String reason = ex.getMessage() == null ? "" : ex.getMessage().toLowerCase();
            if (ex instanceof OAuth2AuthenticationException) {
                boolean expired = reason.contains("expired");
                JsonErrorWriter.write(response, HttpStatus.UNAUTHORIZED,
                        expired ? "TOKEN_EXPIRED" : "TOKEN_INVALID",
                        expired ? "El token expiró, inicia sesión de nuevo" : "Token inválido");
                return;
            }
            JsonErrorWriter.write(response, HttpStatus.UNAUTHORIZED, "TOKEN_REQUIRED",
                    "Falta el token: Authorization: Bearer <jwt>");
        };
        AccessDeniedHandler forbidden = (request, response, ex) -> JsonErrorWriter.write(response,
                HttpStatus.FORBIDDEN, "FORBIDDEN", "Tu rol no permite esta operación");

        // En el login se ignora el Authorization: un token vencido no debe impedir iniciar sesión.
        DefaultBearerTokenResolver defaultResolver = new DefaultBearerTokenResolver();

        http
                .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(e -> e.authenticationEntryPoint(unauthorized).accessDeniedHandler(forbidden))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, LOGIN_PATH).permitAll()
                        .requestMatchers("/health", "/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/auth/register").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.PATCH, "/api/auth/users/*").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.GET, "/api/auth/me").authenticated()
                        .anyRequest().denyAll())
                .oauth2ResourceServer(oauth -> oauth
                        .authenticationEntryPoint(unauthorized)
                        .accessDeniedHandler(forbidden)
                        .bearerTokenResolver(request -> LOGIN_PATH.equals(request.getRequestURI())
                                ? null
                                : defaultResolver.resolve(request))
                        .jwt(jwt -> jwt.decoder(jwtDecoder).jwtAuthenticationConverter(rolesConverter())));
        return http.build();
    }

    /** Claim "role": "ADMIN" -> autoridad ROLE_ADMIN. */
    private static JwtAuthenticationConverter rolesConverter() {
        JwtGrantedAuthoritiesConverter authorities = new JwtGrantedAuthoritiesConverter();
        authorities.setAuthoritiesClaimName(TokenService.ROLE_CLAIM);
        authorities.setAuthorityPrefix("ROLE_");
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authorities);
        return converter;
    }

    private static SecretKey secretKey(AuthProperties props) {
        return new SecretKeySpec(props.jwt().secret().getBytes(StandardCharsets.UTF_8), "HmacSHA256");
    }
}
