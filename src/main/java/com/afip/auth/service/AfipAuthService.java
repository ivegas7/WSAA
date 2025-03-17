package com.afip.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;
import com.afip.auth.model.TokenResponse;
import com.afip.auth.util.LoginTicketRequestGenerator;
import com.afip.auth.util.XmlSigner;
import com.afip.auth.errors.InternalErrorException;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.util.concurrent.TimeUnit;

@Slf4j
@RequiredArgsConstructor
@Service
public class AfipAuthService {

    private final StringRedisTemplate stringRedisTemplate;
    private String token;

    @Value("${service}") // <service> wsfe
    private String service;

    @Value("${config.time_expiration_token}")
    private long timeExpirationToken; // Tiempo de expiración (2h)

    @Value("${endpoint}")
    private String endpoint;

    @Value("${keystore}")
    private String keystore;

    @Value("${keystore-signer}")
    private String keystore_signer;

    @Value("${keystore-password}")
    private String keystore_password;

    public TokenResponse authenticate() {
        try {
            ValueOperations<String, String> ops = stringRedisTemplate.opsForValue();
            token = ops.get("token"); // Recuperar token desde Redis

            // Si el token no existe o ha expirado
            if (token == null || token.trim().isEmpty()) {  // Corregido el condicional
                log.info("El token ha expirado o no existe. Generando un nuevo token.");

                // Generar el XML de solicitud de Ticket
                String loginRequestXml = LoginTicketRequestGenerator.generate(service, timeExpirationToken);
                log.info("LoginTicketRequest XML generado: " + loginRequestXml);

                // Firmar
                byte[] LoginTicketRequest_xml_cms = XmlSigner.createCMS(loginRequestXml, keystore, keystore_password, keystore_signer);
                log.info("LoginTicketRequest_xml_cms: " + LoginTicketRequest_xml_cms);

                // Invocar WSAA para obtener el token
                token = XmlSigner.invoke_wsaa(LoginTicketRequest_xml_cms, endpoint);

                // Expiración del token (2 horas)
                ops.set("token", token, timeExpirationToken, TimeUnit.HOURS);
                log.info("Nuevo Token generado: " + token);

            }

            log.info("Token recuperado: " + token);
            return new TokenResponse(token);

        } catch (Exception e) {
            log.error("Error al generar o validar el token", e);
            throw new InternalErrorException("Error interno al generar o validar el token: " + e.getMessage());
        }
    }
}
