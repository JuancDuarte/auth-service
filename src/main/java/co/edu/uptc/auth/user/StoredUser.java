package co.edu.uptc.auth.user;

/** Fila de la tabla users (la contraseña solo existe como hash BCrypt). */
public record StoredUser(long id, String username, String passwordHash, Role role, Long estudianteId) {
}
