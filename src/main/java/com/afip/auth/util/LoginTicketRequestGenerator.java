package com.afip.auth.util;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class LoginTicketRequestGenerator {
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss");

    public static String generate(String service, long timeExpirationToken) {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime expirationTime = now.plusHours(timeExpirationToken); //add 2 hours
        
        String xml = "<loginTicketRequest>\n" +
                "    <header>\n" +
                "        <uniqueId>" + (System.currentTimeMillis() / 1000) + "</uniqueId>\n" +
                "        <generationTime>" + now.format(FORMATTER) + "</generationTime>\n" +
                "        <expirationTime>" + expirationTime.format(FORMATTER) + "</expirationTime>\n" +
                "    </header>\n" +
                "    <service>" + service + "</service>\n" +
                "</loginTicketRequest>";

        return xml;
    }
}
