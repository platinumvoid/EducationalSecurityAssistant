package org.secknight.secure_web_app.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import java.time.Duration;
import java.time.Instant;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Advanced;
import de.mkammerer.argon2.Argon2Factory;
import de.mkammerer.argon2.Argon2Factory.Argon2Types;

public class Argon2PasswordEncoder implements PasswordEncoder{
	private static Argon2 argon2;
	private static Argon2Advanced argon2adv;
	/*
	 * Argon2d maximizes resistance to GPU cracking attacks. It accesses the memory array in a password dependent order,
	 * which reduces the possibility of time–memory trade-off (TMTO) attacks, but introduces possible side-channel attacks.
	 *
	 * Argon2i is optimized to resist side-channel attacks. It accesses the memory array in a password independent order.
	 *
	 * Argon2id is a hybrid version. It follows the Argon2i approach for the first half pass over memory and the Argon2d approach for subsequent passes.
	 * The Internet draft[4] recommends using Argon2id except when there are reasons to prefer one of the other two modes.
	 *
	 */
	private static final Argon2Types type=Argon2Types.ARGON2id;
	private static final Integer iterations=4; //max=20
	private static final Integer memory=1024*1024;//max= 100000 KB
	private static final Integer threads=2;//max= 10


	private static final Logger LOG = LoggerFactory.getLogger(Argon2PasswordEncoder.class);

	public Argon2PasswordEncoder() {
		argon2 = Argon2Factory.create(type);
	}
	
	public Argon2PasswordEncoder(int saltLength,int  keyLength) {
		argon2adv=Argon2Factory.createAdvanced(type, saltLength,  keyLength);
	}


	@Override
	public String encode(CharSequence rawPassword) {
		if (rawPassword == null) {
			throw new IllegalArgumentException("rawPassword cannot be null");
		}
		Instant beginHash = Instant.now();
		String hash;
		if (argon2adv!=null){

			hash=argon2adv.hash(iterations, memory, threads, rawPassword.toString().toCharArray());
		}else{
			hash=argon2.hash(iterations, memory, threads, rawPassword.toString().toCharArray());
		}
		Instant endHash = Instant.now();
		LOG.info("Encode Process Time:"+Duration.between(beginHash, endHash).toMillis() / 1024.0);
		return hash;
	}

	@Override
	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		if (rawPassword == null) {
			throw new IllegalArgumentException("rawPassword cannot be null");
		}
		if (encodedPassword == null || encodedPassword.length() == 0) {
			LOG.warn("Empty encoded password");
			return false;
		}
		if (!encodedPassword.startsWith("$argon2")) {
			LOG.warn("Encoded password does not look like Argon2");
			return false;
		}

		Instant beginHash = Instant.now();
		boolean success;
		if (argon2adv!=null){
			success = argon2adv.verify(encodedPassword, rawPassword.toString().toCharArray());
		}else{
			success = argon2.verify(encodedPassword, rawPassword.toString().toCharArray());
		}
		Instant endHash = Instant.now();
		LOG.info("Validation Process Time: "+Duration.between(beginHash, endHash).toMillis() / 1024.0);
		return success;
	}
}