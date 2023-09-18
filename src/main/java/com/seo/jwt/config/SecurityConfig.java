package com.seo.jwt.config;

import com.seo.jwt.config.jwt.JwtAuthenticationFilter;
import com.seo.jwt.config.jwt.JwtAuthorizationFilter;
import com.seo.jwt.filter.MyFilter3;
import com.seo.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsFilter corsFilter;
    private final UserRepository userRepository;
    private final CorsConfig corsConfig;
    @Bean
    protected SecurityFilterChain configure(HttpSecurity http) throws Exception {
//        http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class);
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션을 사용하지 않겠다
                .and()
                .addFilter(corsFilter) // @CrossOrigin(인증X), 시큐리티 필터에 등록 인증(O)
                .formLogin().disable()
                .httpBasic().disable()
                .apply(new MyCustomDs1())
                .and()
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll();
        return http.build();
    }

    public class MyCustomDs1 extends AbstractHttpConfigurer<MyCustomDs1, HttpSecurity> {
        @Override
        public void configure(HttpSecurity http) throws Exception {
            AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
            http.addFilter(corsConfig.corsFilter())
                    .addFilter(new JwtAuthenticationFilter(authenticationManager))
                    .addFilter(new JwtAuthorizationFilter(authenticationManager, userRepository));
        }

    }


}
