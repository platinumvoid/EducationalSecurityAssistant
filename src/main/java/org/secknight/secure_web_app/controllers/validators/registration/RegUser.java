package org.secknight.secure_web_app.controllers.validators.registration;

@ValidRegistration
public class RegUser{

	private String username;
	private String email;
	private String password;
	private String retype;

	public String getUsername() {return username;}
	public String getEmail() {return email;}
	public String getPassword() {return password;}
	public String getRetype() {return retype;}

	public void setUsername(String username) {this.username = username;}
	public void setEmail(String email) {this.email = email;}
	public void setPassword(String password) {this.password = password;}
	public void setRetype(String retype) {this.retype = retype;}
}
