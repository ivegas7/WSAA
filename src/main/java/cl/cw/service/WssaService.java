package cl.cw.service;

/**
 * Company: [CrossWave SPA]
 * Project: AFIP Authentication System
 * Author: [Ignacio Vegas Fernández]
 * Description: Description: Authentication service for token generation and management.
 */

import org.mapdb.DB;
import org.mapdb.DBMaker;
import org.mapdb.Serializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import cl.cw.model.TokenResponse;
import cl.cw.util.LoginTicketRequestGenerator;
import cl.cw.util.XmlSigner;

import lombok.extern.slf4j.Slf4j;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;

import java.util.Base64;
import java.util.Map;

@Service
@Slf4j
public class WssaService {

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
        db = DBMaker.fileDB(tokenDbPath)
        		.checksumHeaderBypass()
        		.make();
        
        tokenMap = db.hashMap("tokens", Serializer.STRING, Serializer.JAVA).createOrOpen();

        // Retrieve the token from MapDB
        if (tokenMap.containsKey("token")) {
            String savedToken = (String) tokenMap.get("token");
            Long savedExpirationTime = (Long) tokenMap.get("expirationTime");

            if (savedToken != null && savedExpirationTime != null && savedExpirationTime > System.currentTimeMillis()) {
                token = savedToken;
                expirationTime = savedExpirationTime;
                log.info("Token retrieved from MapDB and is valid.");
            } else {
            	log.info("Expired or not found token, generating a new token.");
            }
        } else {
        	log.info("No persisted token found, generating a new token.");
        }
    }

    public TokenResponse authenticate() {
        try {

            if (token == null || expirationTime < System.currentTimeMillis()) {
            	
                log.info("The token has expired or does not exist. Generating a new token.");
                
                // Generate the Ticket request XML
                String loginRequestXml = LoginTicketRequestGenerator.generate(service, timeExpirationToken);
                log.info("LoginTicketRequest XML generated:");
                log.info(loginRequestXml);
                
                // Sign
                byte[] LoginTicketRequest_xml_cms = XmlSigner.createCMS(loginRequestXml, keystore, keystore_password, keystore_signer);
                log.info("LoginTicketRequest_xml_cms:");
                log.info(Base64.getEncoder().encodeToString(LoginTicketRequest_xml_cms));
                
                // Invoke WSAA to obtain the token
                 token = XmlSigner.invoke_wsaa(LoginTicketRequest_xml_cms, endpoint);
                
                // Save the new token and expiration in MapDB
                generateNewToken(token);
                log.info("New token generated:");
                log.info(token);
                
            } else {
                log.info("Token retrieved from cache: ");
                log.info(token);
            }

            return new TokenResponse(token);
            
        } catch (Exception e) {
            log.error("Error generating or validating the token: " + e.getMessage());
            throw new RuntimeException("Internal error generating or validating the token: " + e.getMessage());
        }
    }

    private void generateNewToken(String token) {
        try {
        	expirationTime = System.currentTimeMillis() +  (timeExpirationToken * 60 * 60 * 1000); 

            tokenMap.put("token", token);
            tokenMap.put("expirationTime", expirationTime);
            db.commit();

            log.info("New token generated and saved in MapDB..");
            
        } catch (Exception e) {
            log.error("Error generating the new token: " + e.getMessage());
            throw new RuntimeException("Internal error generating the new token.: " + e.getMessage());
        }
    }

    @PreDestroy
    public void shutdown() {
        if (db != null) {
            db.close();
        }
    }
}
