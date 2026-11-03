package co.edu.uptc.auth.web;

import co.edu.uptc.auth.error.InvalidCredentialsException;
import co.edu.uptc.auth.error.UserNotFoundException;
import co.edu.uptc.auth.error.UsernameTakenException;
import co.edu.uptc.auth.token.TokenResponse;
import co.edu.uptc.auth.token.TokenService;
import co.edu.uptc.auth.user.UserResponse;
import co.edu.uptc.auth.user.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@Tag(name = "Autenticación", description = "Login, registro (solo ADMIN) y consulta del usuario del token")
public class AuthController {

    private final UserService users;
    private final TokenService tokens;

    public AuthController(UserService users, TokenService tokens) {
        this.users = users;
        this.tokens = tokens;
    }

    @PostMapping("/login")
    @Operation(summary = "Iniciar sesión y obtener un token JWT")
    public TokenResponse login(@Valid @RequestBody LoginRequest request) {
        UserResponse user = users.verify(request.username(), request.password())
                .orElseThrow(InvalidCredentialsException::new);
        return tokens.issue(user);
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Registrar un usuario (rol USER). Requiere token de ADMIN")
    public UserResponse register(@Valid @RequestBody RegisterRequest request) {
        return users.create(request.username(), request.password(), request.estudianteId())
                .orElseThrow(UsernameTakenException::new);
    }

    @PatchMapping("/users/{username}")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Vincular un usuario con un estudiante (claim estudianteId del token). Requiere ADMIN")
    public UserResponse linkEstudiante(@PathVariable String username,
                                       @Valid @RequestBody LinkEstudianteRequest request) {
        return users.linkEstudiante(username, request.estudianteId())
                .orElseThrow(UserNotFoundException::new);
    }

    @GetMapping("/me")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Usuario del token actual")
    public UserResponse me(@Parameter(hidden = true) @AuthenticationPrincipal Jwt jwt) {
        Object estudiante = jwt.getClaim(TokenService.ESTUDIANTE_ID_CLAIM);
        Long estudianteId = estudiante instanceof Number n ? n.longValue() : null;
        return new UserResponse(jwt.getSubject(), jwt.getClaimAsString(TokenService.ROLE_CLAIM), estudianteId);
    }
}
