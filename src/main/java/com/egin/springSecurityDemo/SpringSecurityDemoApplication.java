package com.egin.springSecurityDemo;

import com.egin.springSecurityDemo.auth.AuthenticationService;
import com.egin.springSecurityDemo.auth.RegisterRequest;
import com.egin.springSecurityDemo.user.Role;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SpringSecurityDemoApplication implements CommandLineRunner {


	private final AuthenticationService authenticationService;

	public SpringSecurityDemoApplication(AuthenticationService authenticationService) {
		this.authenticationService = authenticationService;
	}

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityDemoApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {

		var admin = RegisterRequest
				.builder()
				.firstname("Ahmet")
				.lastname("EGIN")
				.email("egnahmet@gmail.com")
				.password("12345")
				.role(Role.ADMIN)
				.build();
		var adminToken = authenticationService.register(admin);
		System.out.println("ADmin TOken: " + adminToken);

		var manager = RegisterRequest
				.builder()
				.firstname("Laur")
				.lastname("Spilca")
				.email("spilca@gmail.com")
				.password("12345")
				.role(Role.MANAGER)
				.build();
		var managerToken = authenticationService.register(manager);
		System.out.println("Manager Token: " + managerToken);


	}
}
