package com.afip.auth.controller;

import com.afip.auth.service.AfipAuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import com.afip.auth.model.TokenResponse;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
public class AfipAuthController {

    private final AfipAuthService afipAuthService;

    @GetMapping("/auth/afip/authenticate")
    public ResponseEntity<TokenResponse> authenticate() {
        log.info("Obteniendo token");
        TokenResponse tokenResponse = afipAuthService.authenticate();
        return ResponseEntity.ok(tokenResponse);
    }
}
