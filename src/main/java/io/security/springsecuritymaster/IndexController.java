package io.security.springsecuritymaster;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class IndexController {

    private final SessionInfoService sessionInfoService;

    @GetMapping("/")
    public Authentication index(Authentication authentication){
        return authentication;
    }

    @GetMapping("/sessionInfo")
    public void sessionInfo() {
        sessionInfoService.sessionInfo();
    }

    @GetMapping("/home")
    public String home() {
        return "home";
    }

    @GetMapping("/loginPage")
    public String loginPage() {
        return "loginPage";
    }

    @GetMapping("/anonymous")
    public String anonymous() {
        return "anonymous";
    }

    @GetMapping("/authentication")
    public String authentication(Authentication authentication) {
        if (authentication instanceof AnonymousAuthenticationToken) {
            return "is anonymous";
        } else {
            // org.springframework.security.authentication.UsernamePasswordAuthenticationToken
            return "not anonymous";
        }
    }

    @GetMapping("/anonymousContext")
    public String anonymousContext(@CurrentSecurityContext SecurityContext securityContext) {
        return securityContext.getAuthentication().getName();
    }

    @GetMapping("/invalidSessionUrl")
    public String invalidSessionUrl(){
        return "invalidSessionUrl";
    }

    @GetMapping("/expired")
    public String expired(){
        return "expired";
    }

    @GetMapping("/login")
    public String login() {
        return "loginPage";
    }

    @GetMapping("/denied")
    public String denied() {
        return "denied";
    }

}
