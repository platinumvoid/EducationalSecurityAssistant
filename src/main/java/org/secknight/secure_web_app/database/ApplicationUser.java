package org.secknight.secure_web_app.database;

import java.util.Collection;
import java.util.Objects;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class ApplicationUser implements UserDetails{

	private static final long serialVersionUID = -6559273573361401533L;
	/*Required Fields*/
	private final String username;
	private final String password;
	private final Set<? extends GrantedAuthority> grantedAuthorities;
	private final boolean isAccountNonExpired;
	private final boolean isAccountNonLocked;
	private final boolean isCredentialsNonExpired;
	private final boolean isEnabled;
	/*Additional Fields*/
	private final String email;

	public ApplicationUser(
			String username, 
			String email, 
			String password,
			Set<? extends GrantedAuthority> grantedAuthorities,
			boolean isAccountNonExpired, 
			boolean isAccountNonLocked, 
			boolean isCredentialsNonExpired,
			boolean isEnabled) {

		this.username = username;
		this.email = email;
		this.password = password;
		this.grantedAuthorities = grantedAuthorities;
		this.isAccountNonExpired = isAccountNonExpired;
		this.isAccountNonLocked = isAccountNonLocked;
		this.isCredentialsNonExpired = isCredentialsNonExpired;
		this.isEnabled = isEnabled;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return grantedAuthorities;
	}

	@Override
	public String getPassword() {
		return password;
	}

	@Override
	public String getUsername() {
		return username;
	}

	@Override
	public boolean isAccountNonExpired() {
		return isAccountNonExpired;
	}

	@Override
	public boolean isAccountNonLocked() {
		return isAccountNonLocked;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return isCredentialsNonExpired;
	}

	@Override
	public boolean isEnabled() {
		return isEnabled;
	}

	public String getEmail() {
		return email;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof ApplicationUser)) return false;
		ApplicationUser that = (ApplicationUser) o;
		return username.equals(that.username) &&
				email.equals(that.email) &&
				password.equals(that.password);
	}

	@Override
	public int hashCode() {
		return Objects.hash(username, email, password);
	}

	@Override
	public String toString() {
		return "ApplicationUser{" +
				"username='" + username + '\'' +
				", password='" + password + '\'' +
				", grantedAuthorities=" + grantedAuthorities +
				", isAccountNonExpired=" + isAccountNonExpired +
				", isAccountNonLocked=" + isAccountNonLocked +
				", isCredentialsNonExpired=" + isCredentialsNonExpired +
				", isEnabled=" + isEnabled +
				", email='" + email + '\'' +
				'}';
	}
}
