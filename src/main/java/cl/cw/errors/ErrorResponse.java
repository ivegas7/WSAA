package cl.cw.errors;

/**
 * Company: [CrossWave SPA]
 * Project: AFIP Authentication System
 * Author: [Ignacio Vegas Fernández]
 * Description: Represents the error response structure for API errors.
 */

import lombok.Data;

@Data
public class ErrorResponse {
    private int statusCode; 
    private String error;
    private String message;
    private String path;
    private long timestamp;

    public ErrorResponse(int statusCode, String error, String message, String path) {
        this.statusCode = statusCode;
        this.message = message;
        this.error = error;
        this.path = path;
        this.timestamp = System.currentTimeMillis();
    }
}