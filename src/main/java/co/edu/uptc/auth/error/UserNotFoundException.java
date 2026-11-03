package co.edu.uptc.auth.error;

public class UserNotFoundException extends RuntimeException {

    public UserNotFoundException() {
        super("El usuario no existe");
    }
}
