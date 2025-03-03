package kr.co.kst.auth.ui;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import kr.co.kst.auth.application.AuthService;
import kr.co.kst.auth.dto.LoginRequest;
import kr.co.kst.auth.dto.LoginResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;

@RestController
@RequestMapping("auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public void login(@RequestBody LoginRequest loginRequest, HttpServletResponse response) {
        LoginResponse loginResponse = authService.login(loginRequest.id(), loginRequest.password());
        ResponseCookie cookie = ResponseCookie.from("access_token", loginResponse.token())
                .httpOnly(true)
                .secure(false)      //localhost
                .path("/")
                .maxAge(60 * 30)
                .sameSite("Strict")
                .build();
        response.setHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    @PostMapping("valid")
    public ResponseEntity<String> valid(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        Cookie token =  Arrays.stream(cookies)
                .filter(cookie -> cookie.getName().equals("access_token"))
                .findFirst()
                .orElseThrow();
        return ResponseEntity.ok(token.getValue());
    }
}
