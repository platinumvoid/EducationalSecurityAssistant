package org.secknight.secure_web_app.controllers.validators.registration;

import java.util.Collections;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import org.passay.CharacterCharacteristicsRule;
import org.passay.CharacterRule;
import org.passay.EnglishCharacterData;
import org.passay.LengthRule;
import org.passay.PasswordData;
import org.passay.PasswordValidator;
import org.passay.RuleResult;
import com.google.common.base.CharMatcher;

public class RegistrationValidation implements ConstraintValidator<ValidRegistration, RegUser> {

	/**
	 * Length Min 8 characters NIST SP800-63B Set Max to prevent long password DoS
	 * attacks Because we are using BCrypt (max 72) we have selected 64 to not
	 * reveal it outside
	 * https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.
	 * html#maximum-password-lengths
	 */
	private static final PasswordValidator passwordValidator = new PasswordValidator(
			Collections.singletonList(new LengthRule(8, 64)));

	private static final CharacterCharacteristicsRule characterCharacteristicsRule = new CharacterCharacteristicsRule(
			4, 
			new CharacterRule(EnglishCharacterData.LowerCase, 1), 
			new CharacterRule(EnglishCharacterData.UpperCase, 1), 
			new CharacterRule(EnglishCharacterData.Digit,1),
			new CharacterRule(EnglishCharacterData.Special,1)
			);

	@Override
	public void initialize(ValidRegistration arg0) {}

	@Override
	public boolean isValid(RegUser user, ConstraintValidatorContext context) {
		String error_message="";
		boolean valid=true;
		/*Username Checker*/
		if(user.getUsername()==null || user.getUsername().equals("")) {
			error_message+="Username: Please enter your Username\n";
			valid=false;
		}else {
			//Change according to your policy requirements
			String username_pattern = "^[a-zA-Z0-9]+$";
			Matcher m = Pattern.compile(username_pattern).matcher(user.getUsername());
			if (!m.find()) {
				error_message+="Username: Only alphanumeric characters allowed (a-z,0-9)\n";
				valid=false;
			}
		}		

		/*Email Checker*/
		if(user.getEmail()==null || user.getEmail().equals("")) {
			error_message+="Email: Please enter an Email Address\n";
			valid=false;
		}else if(!CharMatcher.ascii().matchesAllOf(user.getEmail())){
			error_message+="Password: Invalid Characters\n";
			valid=false;
		}else {
			String email_pattern  = "(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)"
					+ "*|\"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]"
					+ "|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]"
					+ "*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:25[0-5]|2[0-4]"
					+ "[0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]"
					+ "*[a-z0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01"
					+ "-\\x09\\x0b\\x0c\\x0e-\\x7f])+)])";

			Matcher m = Pattern.compile(email_pattern).matcher(user.getEmail());
			if (!m.find()) {
				error_message+="Email: Please enter a valid Email Address\n";
				valid=false;
			}
		}

		/*Password Checker*/
		if (user.getPassword()==null || user.getPassword().equals("")) {
			error_message+="Password: Please enter your Password\n";
			valid=false;
		}else if(!CharMatcher.ascii().matchesAllOf(user.getPassword())){
			error_message+="Password: Invalid Characters\n";
			valid=false;
		}else{
			RuleResult result1 = passwordValidator.validate(new PasswordData(user.getPassword()));
			RuleResult result2 = characterCharacteristicsRule.validate(new PasswordData(user.getPassword()));
			if (!result1.isValid() || !result2.isValid()) {
				error_message+="Password: Password must be at least 8 characters<br>Contain one of each: lowercase, UPPERCASE, Digit, Special Character\n";
				valid=false;
			}
		}

		/*Retype Checker*/
		if (user.getPassword()==null || user.getRetype()==null || user.getPassword().equals("") || user.getRetype().equals("")) {
			error_message+="Retype: Passwords not match\n";
			valid=false;
		}else {
			boolean match=user.getPassword().equals(user.getRetype());
			if (!match) {
				error_message+="Retype: Passwords not match\n";
				valid=false;
			}
		}
		context.disableDefaultConstraintViolation();
		context.buildConstraintViolationWithTemplate(error_message).addConstraintViolation();
		return valid;
	}
}