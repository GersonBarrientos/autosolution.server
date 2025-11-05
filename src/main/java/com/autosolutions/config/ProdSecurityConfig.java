package com.autosolutions.config;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;

@Configuration
@Profile("prod") // Activo sólo cuando arrancas con --spring.profiles.active=prod
public class ProdSecurityConfig {

    /**
     * Rutas totalmente ignoradas por el filtro de Spring Security.
     * Útiles para healthchecks simples, robots.txt, etc.
     * (NO ignores aquí /actuator/** completo para no perder protección)
     */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring().requestMatchers(
            "/status",     // si expones un ping simple
            "/robots.txt"
        );
    }

    /**
     * Reglas de seguridad para producción:
     * - CSRF con cookie (para formularios Thymeleaf)
     * - Recursos estáticos y login públicos
     * - Si usas Actuator, abre sólo health e info
     * - Resto autenticado
     * - Cabeceras de seguridad razonables
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // CSRF con cookie (visible para JS si lo necesitas)
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            )

            // Autorizaciones
            .authorizeHttpRequests(auth -> auth
                // Recursos estáticos comunes de Spring Boot
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
                // WebJars y recursos propios
                .requestMatchers(
                    "/webjars/**",
                    "/css/**",
                    "/js/**",
                    "/images/**",
                    "/favicon.ico",
                    "/error",
                    "/login",
                    "/status" // match con lo ignorado (permite accesos directos)
                ).permitAll()
                // Si usas Actuator, abre sólo health/info
                .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                // Todo lo demás requiere autenticación
                .anyRequest().authenticated()
            )

            // Form Login clásico (usa tu vista /login)
            .formLogin(form -> form
                .loginPage("/login")
                .loginProcessingUrl("/login")
                .usernameParameter("username")
                .passwordParameter("password")
                .failureUrl("/login?error")
                .defaultSuccessUrl("/", true)
                .permitAll()
            )

            // Logout estándar
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
                .permitAll()
            )

            // Cabeceras de seguridad (no intrusivas)
            .headers(headers -> headers
                // X-XSS-Protection header and its DSL support have been removed/deprecated in newer Spring Security;
                // omit it to avoid using unsupported API and because modern browsers ignore this header.
                .contentTypeOptions(c -> {}) // X-Content-Type-Options: nosniff
                .frameOptions(f -> f.sameOrigin())
                .referrerPolicy(r -> r.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
                .httpStrictTransportSecurity(hsts -> hsts
                    .includeSubDomains(true)
                    .preload(false)            // pon true si usas HTTPS en todos los subdominios
                    .maxAgeInSeconds(31536000) // 1 año
                )
            );

        // Importante: sin httpBasic() en prod (menos superficie)
        return http.build();
    }

    /**
     * Encoder estándar (BCrypt). Útil si autenticas contra BD.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
