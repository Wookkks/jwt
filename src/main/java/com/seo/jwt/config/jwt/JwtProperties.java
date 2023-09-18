package com.seo.jwt.config.jwt;

public interface JwtProperties {
    String SECRET = "seo"; // 우리 서버만 알고 있는 비밀값
    int EXPRIATION_TIME = 60000*10; // 10분 (1/1000초)
    String TOKEN_PREFIX = "Bearer ";
    String HEADER_STRING = "Authorization";
}
