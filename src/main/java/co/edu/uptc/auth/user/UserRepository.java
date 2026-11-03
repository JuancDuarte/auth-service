package co.edu.uptc.auth.user;

import java.util.Optional;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

/** Acceso a la base de datos propia del módulo (tabla users). */
@Repository
public class UserRepository {

    private static final RowMapper<StoredUser> MAPPER = (rs, i) -> new StoredUser(
            rs.getLong("id"),
            rs.getString("username"),
            rs.getString("password_hash"),
            Role.valueOf(rs.getString("role")),
            rs.getObject("estudiante_id", Long.class));

    private final JdbcTemplate jdbc;

    public UserRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Optional<StoredUser> findByUsername(String username) {
        return jdbc.query(
                "SELECT id, username, password_hash, role, estudiante_id FROM users WHERE lower(username) = lower(?)",
                MAPPER, username).stream().findFirst();
    }

    /** @return false si el nombre ya existe (índice único sobre lower(username)). */
    public boolean insert(String username, String passwordHash, Role role, Long estudianteId) {
        try {
            jdbc.update("INSERT INTO users (username, password_hash, role, estudiante_id) VALUES (?, ?, ?, ?)",
                    username, passwordHash, role.name(), estudianteId);
            return true;
        } catch (DuplicateKeyException e) {
            return false;
        }
    }

    /** @return filas actualizadas (0 si el usuario no existe). */
    public int updateEstudianteId(String username, Long estudianteId) {
        return jdbc.update("UPDATE users SET estudiante_id = ? WHERE lower(username) = lower(?)",
                estudianteId, username);
    }
}
