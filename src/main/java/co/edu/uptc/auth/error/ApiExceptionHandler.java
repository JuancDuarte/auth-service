package co.edu.uptc.auth.error;

import java.util.List;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> validation(MethodArgumentNotValidException ex) {
        List<Map<String, String>> details = ex.getBindingResult().getFieldErrors().stream()
                .map(e -> Map.of("field", e.getField(),
                        "message", e.getDefaultMessage() != null ? e.getDefaultMessage() : "inválido"))
                .toList();
        return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY)
                .body(ApiError.of("VALIDATION_ERROR", "El cuerpo no cumple las reglas de validación", details));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiError> badJson(HttpMessageNotReadableException ex) {
        return ResponseEntity.badRequest().body(ApiError.of("INVALID_JSON", "JSON mal formado o faltante"));
    }

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<ApiError> invalidCredentials(InvalidCredentialsException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ApiError.of("INVALID_CREDENTIALS", "Usuario o contraseña incorrectos"));
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ApiError> userNotFound(UserNotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(ApiError.of("USER_NOT_FOUND", "El usuario no existe"));
    }

    @ExceptionHandler(UsernameTakenException.class)
    public ResponseEntity<ApiError> usernameTaken(UsernameTakenException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(ApiError.of("USERNAME_TAKEN", "Ese nombre de usuario ya existe"));
    }
}
