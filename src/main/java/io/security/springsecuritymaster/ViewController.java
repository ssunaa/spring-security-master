package io.security.springsecuritymaster;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ViewController {

    @GetMapping("/cookie")
    public String cookie() {
        return "cookie";
    }

    @GetMapping("/form")
    public String form() {
        return "form";
    }
}
