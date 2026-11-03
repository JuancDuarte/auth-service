package co.edu.uptc.auth.web;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

public record LinkEstudianteRequest(
        @Schema(example = "12", description = "Id del estudiante en el módulo Estudiantes")
        @NotNull @Positive Long estudianteId) {
}
