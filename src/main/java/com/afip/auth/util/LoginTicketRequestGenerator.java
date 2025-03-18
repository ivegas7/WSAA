package com.afip.auth.util;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class LoginTicketRequestGenerator {
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'");

    public static String generate(String service, long timeExpirationToken) {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime expirationTime = now.plusHours(timeExpirationToken);

        System.out.println("[LOG] Expiration now: " + now);
        System.out.println("[LOG] Expiration exp: " + expirationTime);
        
        String xml = "<loginTicketRequest>" +
                "<header>" +
                "<uniqueId>" + (System.currentTimeMillis() / 1000) + "</uniqueId>" +
                "<generationTime>" + now.format(FORMATTER) + "</generationTime>" +
                "<expirationTime>" + expirationTime.format(FORMATTER) + "</expirationTime>" +
                "</header>" +
                "<service>" + service + "</service>" +
                "</loginTicketRequest>";

        return xml;
    }
}
