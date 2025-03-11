package com.afip.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;

import com.afip.auth.model.TokenResponse;
import com.afip.auth.util.LoginTicketRequestGenerator;
import com.afip.auth.util.XmlSigner;

import java.time.Instant;

@Slf4j
@RequiredArgsConstructor
@Service
public class AfipAuthService {

    private String token;
    private long tokenExpirationTime;

    @Value("${service}") // <servive> wsfe
    private String service;

    @Value("${config.time_expiration_token}")
    private long timeExpirationToken; // Tiempo de expiración (2h)

    @Value("${http_proxy}")
    private String http_proxy;

    @Value("${http_proxy_port}")
    private String http_proxy_port;

    @Value("${endpoint}")
    private String endpoint;

    @Value("${keystore}")
    private String keystore;

    @Value("${keystore-signer}")
    private String keystore_signer;

    @Value("${keystore-password}")
    private String keystore_password;

    @Value("${trustStore}")
    private String trustStore;

    @Value("${trustStore_password}")
    private String trustStore_password;

    public TokenResponse authenticate() {
        try {
            long currentTime = Instant.now().toEpochMilli();

            // Si el token no existe o ha expirado
            if (token == null || currentTime >= tokenExpirationTime) {
                log.info("El token ha expirado o no existe. Generando un nuevo token.");

                // Generar el XML de solicitud de Ticket
                String loginRequestXml = LoginTicketRequestGenerator.generate(service,timeExpirationToken);
                log.info("LoginTicketRequest XML generado: " + loginRequestXml);

                //Firmar
                byte[] LoginTicketRequest_xml_cms = XmlSigner.createCMS(loginRequestXml, keystore, keystore_password, keystore_signer);
                System.out.println("LoginTicketRequest_xml_cms: " + LoginTicketRequest_xml_cms);
                
                // Invocar WSAA para obtener el token
                try {
                    token = XmlSigner.invokeWSAA(LoginTicketRequest_xml_cms, endpoint);
                    log.info("Token generado:");
                    System.out.println(token);
                } catch (Exception e) {
                    log.error("Error al invocar WSAA", e);
                    return null;
                }

                // Expiración del token (2 horas)
                //tokenExpirationTime = currentTime + (timeExpirationToken * 60 * 60 * 1000); // Expiración en milisegundos
                tokenExpirationTime = currentTime + (20 * 1000);  // 10s
            }

            return new TokenResponse(token);

        } catch (Exception e) {
            log.error("Error al generar o validar el token", e);
            return null;
        }
    }
}
