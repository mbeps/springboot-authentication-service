package com.maruf.auth.service;

import com.maruf.auth.entity.User;
import com.maruf.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class LocalAuthService {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;

	public User register(String email, String password, String name) {
		if (userRepository.existsByEmail(email)) {
			throw new IllegalArgumentException("Email already in use");
		}

		User user = User.builder()
				.email(email)
				.password(passwordEncoder.encode(password))
				.name(name)
				.roles(Collections.singletonList("ROLE_USER"))
				.build();

		return userRepository.save(user);
	}

	public Optional<User> login(String email, String password) {
		Optional<User> userOpt = userRepository.findByEmail(email);
		if (userOpt.isPresent()) {
			User user = userOpt.get();
			if (passwordEncoder.matches(password, user.getPassword())) {
				return Optional.of(user);
			}
		}
		return Optional.empty();
	}
}
