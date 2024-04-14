package io.security.springsecuritymaster;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // 인가정책 설정
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/anonymous").hasRole("GUEST")
                        .requestMatchers("/anonymousContext", "authentication").permitAll()
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .anonymous(anonymous -> anonymous
                        .principal("guest")
                        .authorities("ROLE_GUEST"))
                .rememberMe(rememberMe -> rememberMe
//                        .alwaysRemember(true)
                        .tokenValiditySeconds(3600)
                        .userDetailsService(userDetailService())
                        .rememberMeParameter("remember")
                        .rememberMeCookieName("remember")
                        .key("security")
                );

                // .httpBasic(basic -> basic.authenticationEntryPoint(new CustomAuthenticationEntryPoint()));
                /*
                .formLogin(
                        form -> form
//                                .loginPage("/loginPage")
                                .loginProcessingUrl("/loginProc")
                                .defaultSuccessUrl("/", false)
                                .failureUrl("/failed")
                                .usernameParameter("userId")
                                .usernameParameter("passwd")
                                .successHandler((request, response, authentication) -> {
                                    System.out.println("authentication : " + authentication);
                                    response.sendRedirect("/home");
                                })
                                .failureHandler((request, response, exception) -> {
                                    System.out.println("exception : " + exception.getMessage());
                                    response.sendRedirect("/login");
                                })
                                .permitAll()

                );
                 */
        return http.build();
    }

    private UserDetailsService userDetailService() {
        return null;
    }

    @Bean
    public InMemoryUserDetailsManager inMemoryUserDetailsManager() {
        UserDetails user = User.withUsername("user2")
                .password("{noop}2222")
                .authorities("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }
}
