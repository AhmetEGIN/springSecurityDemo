package com.egin.springSecurityDemo.demo;

import com.egin.springSecurityDemo.auth.AuthenticationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/demo")
public class DemoController {


    private final AuthenticationService authenticationService;

    public DemoController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @GetMapping
    public ResponseEntity<String> demo(){
        return ResponseEntity.ok("Hello");
    }


    @GetMapping("/test")
    public ResponseEntity<String> test() {
        return ResponseEntity.ok(authenticationService.test());
    }

}
