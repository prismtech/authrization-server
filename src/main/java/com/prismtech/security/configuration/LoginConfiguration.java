package com.prismtech.security.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.List;

@EnableWebSecurity
public class LoginConfiguration {
	@Bean
	@Order(3)
	SecurityFilterChain loginSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
		httpSecurity
				.csrf().disable()
				.headers().frameOptions().disable().and()
				.authorizeRequests()
				.antMatchers("/login/**").permitAll()
				.antMatchers("/css/**").permitAll()
				.antMatchers("/images/**").permitAll()
				.antMatchers("/authorized").permitAll()
				.antMatchers("/authorized-local").permitAll()
				.antMatchers("/employee-session").permitAll()
				.anyRequest().authenticated()
				.and()
				.formLogin().loginPage("/login");
		return httpSecurity.build();
	}

	@Bean
	@Order(2)
	SecurityFilterChain configureSecurityFilterChain(HttpSecurity http) throws Exception {

		http
				.authorizeHttpRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated())
				.formLogin(Customizer.withDefaults());

		return http.build();

	}

	@Bean
	public UserDetailsService users() {

		PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

		UserDetails user1 = User.withUsername("user1")
				.password(encoder.encode("password"))
				.roles("USER")
				.build();

		UserDetails user2 = User.withUsername("user2")
				.password(encoder.encode("password"))
				.roles("USER")
				.build();

		List<UserDetails> userDetailsList = new ArrayList<>();
		userDetailsList.add(user1);
		userDetailsList.add(user2);

		return new InMemoryUserDetailsManager(userDetailsList);
	}
}
