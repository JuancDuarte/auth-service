package co.edu.uptc.auth.user;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record UserResponse(
        @Schema(example = "admin") String username,
        @Schema(example = "ADMIN", allowableValues = {"ADMIN", "USER"}) String role,
        @Schema(example = "12", description = "Id del estudiante vinculado (solo usuarios estudiantes)")
        Long estudianteId) {

    public UserResponse(String username, String role) {
        this(username, role, null);
    }
}
