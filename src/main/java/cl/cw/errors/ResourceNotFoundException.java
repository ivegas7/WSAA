package cl.cw.errors;

/**
 * Company: [CrossWave SPA]
 * Project: AFIP Authentication System
 * Author: [Ignacio Vegas Fernández]
 * Description: Custom exception for handling resource not found errors.
 */

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.NOT_FOUND)
public class ResourceNotFoundException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public ResourceNotFoundException(String message) {
        super(message);
    }
}
