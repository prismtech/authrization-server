package com.prismtech.security.controllers;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {
	
	@RequestMapping("/login")
	public String loginPage() {
		return "login";
	}
	
}
