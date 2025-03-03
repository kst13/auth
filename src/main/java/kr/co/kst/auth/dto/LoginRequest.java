package kr.co.kst.auth.dto;

public record LoginRequest(
        String id,
        String password
) {
}
