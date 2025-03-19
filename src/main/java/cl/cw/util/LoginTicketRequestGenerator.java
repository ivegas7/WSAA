package cl.cw.util;

/**
 * Company: [CrossWave SPA]
 * Project: AFIP Authentication System
 * Author: [Ignacio Vegas Fernández]
 * Description: Authentication ticket generator for AFIP services.
 */

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class LoginTicketRequestGenerator {
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'");

    public static String generate(String service, long timeExpirationToken) {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime expirationTime = now.plusHours(timeExpirationToken);

        log.info("Date now: " + now);
        log.info("Date Expiration: " + expirationTime);

        String xml = String.format(
            "<loginTicketRequest>\n" +
            "    <header>\n" +
            "        <uniqueId>%d</uniqueId>\n" +
            "        <generationTime>%s</generationTime>\n" +
            "        <expirationTime>%s</expirationTime>\n" +
            "    </header>\n" +
            "    <service>%s</service>\n" +
            "</loginTicketRequest>",
            System.currentTimeMillis() / 1000,
            now.format(FORMATTER),
            expirationTime.format(FORMATTER),
            service
        );

        return xml;
    }

}
