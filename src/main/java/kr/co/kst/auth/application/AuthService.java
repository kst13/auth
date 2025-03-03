package kr.co.kst.auth.application;

import kr.co.kst.auth.dto.LoginResponse;
import kr.co.kst.auth.security.TokenProvider;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final TokenProvider tokenProvider;

    public AuthService(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }


    public LoginResponse login(String memberId, String password) {
        String token = tokenProvider.createToken(memberId);

        return new LoginResponse(token);
    }
}
