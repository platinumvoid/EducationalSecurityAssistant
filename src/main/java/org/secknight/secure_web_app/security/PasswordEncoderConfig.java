package org.secknight.secure_web_app.security;

import java.security.SecureRandom;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class PasswordEncoderConfig {

	private static final String encoder="BCrypt";

	/**
	 * Test ArgonEncoder:
	 * username: argonTest
	 * password: 9gDxJ9Zp#
	 * Note: Other users will not be able to login
	 * due to their passwords are encoded with Bcrypt
	 * @return
	 */
	@Bean
	public PasswordEncoder passwordEncoder() {
		if (encoder.contentEquals("Argon")){
			return new Argon2PasswordEncoder();
		}else if (encoder.contentEquals("ArgonAdvanced")){
			return new Argon2PasswordEncoder(16,16);
		}else{
			return new BCryptPasswordEncoder (12, new SecureRandom());
		}
	}
}
