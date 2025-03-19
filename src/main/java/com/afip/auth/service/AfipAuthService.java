package com.afip.auth.service;

import org.mapdb.DB;
import org.mapdb.DBMaker;
import org.mapdb.Serializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.afip.auth.model.TokenResponse;
import com.afip.auth.util.LoginTicketRequestGenerator;
import com.afip.auth.util.XmlSigner;

import lombok.extern.slf4j.Slf4j;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.util.Map;

@Service
@Slf4j
public class AfipAuthService {

    private String token;

    @Value("${service}")
    private String service;

    private long expirationTime; 

    @Value("${endpoint}")
    private String endpoint;

    @Value("${keystore}")
    private String keystore;

    @Value("${keystore-signer}")
    private String keystore_signer;

    @Value("${keystore-password}")
    private String keystore_password;
    
    @Value("${config.time_expiration_token}")
    private long timeExpirationToken; 
    
    @Value("${token.db.path}")
    private String tokenDbPath;
    
    private DB db;
    private Map<String, Object> tokenMap;


    @PostConstruct
    public void init() {
        db = DBMaker.fileDB(tokenDbPath).make();
        tokenMap = db.hashMap("tokens", Serializer.STRING, Serializer.JAVA).createOrOpen();

        // Recuperamos el token de MapDB
        if (tokenMap.containsKey("token")) {
            String savedToken = (String) tokenMap.get("token");
            Long savedExpirationTime = (Long) tokenMap.get("expirationTime");

            if (savedToken != null && savedExpirationTime != null && savedExpirationTime > System.currentTimeMillis()) {
                token = savedToken;
                expirationTime = savedExpirationTime;
                log.info("Token recuperado desde MapDB y es válido");
            } else {
            	log.info("Token expirado o no encontrado, generando nuevo token.");
            }
        } else {
        	log.info("No se encontró token persistido, generando nuevo token.");
        }
    }

    public TokenResponse authenticate() {
        try {

            if (token == null || expirationTime < System.currentTimeMillis()) {
            	
                log.info("El token ha expirado o no existe. Generando un nuevo token.");
                
                // Generar el XML de solicitud de Ticket
                String loginRequestXml = LoginTicketRequestGenerator.generate(service, timeExpirationToken);
                log.info("LoginTicketRequest XML generado: " + loginRequestXml);
                
                // Firmar
                byte[] LoginTicketRequest_xml_cms = XmlSigner.createCMS(loginRequestXml, keystore, keystore_password, keystore_signer);
                log.info("LoginTicketRequest_xml_cms: " + LoginTicketRequest_xml_cms);
                
                // Invocar WSAA para obtener el token
                 token = XmlSigner.invoke_wsaa(LoginTicketRequest_xml_cms, endpoint);
                
                // Guardamos el nuevo token y la expiración en MapDB
                generateNewToken(token);
                log.info("Nuevo Token generado: " + token);
                
            } else {
                log.info("Token recuperado de caché: " + token);
            }

            return new TokenResponse(token);
        } catch (Exception e) {
            log.error("Error al generar o validar el token: " + e.getMessage());
            throw new RuntimeException("Error interno al generar o validar el token: " + e.getMessage());
        }
    }

    private void generateNewToken(String token) {
        try {
        	expirationTime = System.currentTimeMillis() +  (timeExpirationToken * 60 * 60 * 1000); 

            tokenMap.put("token", token);
            tokenMap.put("expirationTime", expirationTime);
            db.commit();

            log.info("Nuevo token generado y guardado en MapDB.");
            
        } catch (Exception e) {
            log.error("Error al generar el nuevo token: " + e.getMessage());
            throw new RuntimeException("Error interno al generar el nuevo token: " + e.getMessage());
        }
    }

    @PreDestroy
    public void shutdown() {
        if (db != null) {
            db.close();
        }
    }
}
