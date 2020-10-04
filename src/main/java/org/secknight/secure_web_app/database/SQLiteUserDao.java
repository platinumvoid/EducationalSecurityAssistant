package org.secknight.secure_web_app.database;

import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;
import com.google.common.collect.Sets;

@Repository("sqlite_dao")
public class SQLiteUserDao {
	private static final Logger logger = LoggerFactory.getLogger(SQLiteUserDao.class);
	
	@Autowired
	private JdbcTemplate jdbcTemplate;

	@Autowired
	private PasswordEncoder passwordEncoder;

	
	public ApplicationUser getUserDetails(String username, String email) {
		try {
			User user_details=jdbcTemplate.query(
							"SELECT * FROM Users WHERE Username=? OR Email=?",
							preparedStatement -> {
								preparedStatement.setString(1, username);
								preparedStatement.setString(2, email);
								},
							resultSet -> {
								if (resultSet.next()) {
									return new User(resultSet.getInt("ID"),
											resultSet.getString("Username"),
											resultSet.getString("Email"),
											resultSet.getString("Password"),
											resultSet.getInt("isAccountNonExpired"),
											resultSet.getInt("isAccountNonLocked"),
											resultSet.getInt("isCredentialsNonExpired"),
											resultSet.getInt("isEnabled"));
								}
								else return null;
							});
			if (user_details==null){ return null; }

			List<Role> roles=jdbcTemplate.query(
					"SELECT DISTINCT C.RoleName, C.RoleDescription FROM UsertoRole AS A INNER JOIN Users AS B ON A.UserID=B.ID INNER JOIN Roles AS C ON A.RoleID=C.ID WHERE B.Username=? OR B.Email=?",
					preparedStatement -> {
						preparedStatement.setString(1, username);
						preparedStatement.setString(2, email);
						},
					resultSet -> {
						List<Role> list=new ArrayList<>();
						while(resultSet.next()) {
							list.add(new Role(resultSet.getString("RoleName"),resultSet.getString("RoleDescription")));
						}
						return list;
					});

			List<String> permissions=jdbcTemplate.query(
					"SELECT PermissionName FROM Permissions AS E INNER JOIN	(SELECT DISTINCT C.PermissionID FROM RoletoPermission AS C INNER JOIN (SELECT RoleID FROM UsertoRole as A INNER JOIN Users as B ON A.UserID=B.ID WHERE B.Username=? OR B.Email=?)S on C.RoleID=S.RoleID)X on E.ID = X.PermissionID",
					preparedStatement -> {
						preparedStatement.setString(1, username);
						preparedStatement.setString(2, email);
						},
					resultSet -> {
						List<String> list=new ArrayList<>();
						while(resultSet.next()) {
							list.add(resultSet.getString("PermissionName"));
						}
						return list;
					});

			assert roles != null;
			return new ApplicationUser(
					user_details.getUsername(),user_details.getEmail(),user_details.getPassword(),
					getGrantedAuthorities(roles,permissions),
					user_details.getIsAccountNonExpired()==1,
					user_details.getIsAccountNonLocked()==1,
					user_details.getIsCredentialsNonExpired()==1,
					user_details.getIsEnabled()==1
			);
		}catch(DataAccessException dae) {
			logger.error("SQLiteUserDao: "+dae.getMessage());
			return null;
		}
	}

	/**
	 * If user already exists then send false.
	 * @param username username
	 * @param email email
	 * @return exists false, otherwise true
	 */
	public boolean checkIfUserExists(String username, String email) {
		try{
		Boolean exists=jdbcTemplate.query(
				"SELECT ID FROM Users WHERE Username=? or Email=?",
				preparedStatement -> {
					preparedStatement.setString(1, username);
					preparedStatement.setString(2, email);
				},
				ResultSet::next
		);
		if (exists!=null){
			return exists;
		}else return false;
		}catch (DataAccessException dae){
			logger.error("SQLiteUserDao: "+dae.getMessage());
			return true;
		}
	}

	/**
	 * Registers a new User
	 * @param username Username
	 * @param email Email
	 * @param password Password
	 * @return 1 if insertion was successful or 0 otherwise
	 */
	public int registerNewUser(String username, String email, String password){
		try {
			int status1 = jdbcTemplate.update(
					"INSERT INTO Users (Username,Email,Password,isAccountNonExpired,isAccountNonLocked,isCredentialsNonExpired,isEnabled) VALUES "
							+ "(?,?,?,1,1,1,1)",
					preparedStatement -> {
						preparedStatement.setString(1, username);
						preparedStatement.setString(2, email);
						preparedStatement.setString(3, passwordEncoder.encode(password));
					});
			int status2 = jdbcTemplate.update(
					"INSERT INTO UsertoRole (UserID,RoleID)\n" +
							"SELECT A.ID, B.ID FROM Users AS A, Roles AS B\n" +
							"WHERE A.Username=? AND B.RoleName=?;",
					preparedStatement -> {
						preparedStatement.setString(1, username);
						preparedStatement.setString(2, "USER");

					});

			if (status1 == 0 || status2 == 0) return 0;
			else return 1;
		}catch (DataAccessException dae){
			logger.error("SQLiteUserDao: "+dae.getMessage());
			return 0;
		}
	}

	public Set<SimpleGrantedAuthority> getGrantedAuthorities(List<Role> roles,List<String> permissions){
		Set<SimpleGrantedAuthority> grantedAuthorities=Sets.newHashSet();
		int i = 0;
		while (i < roles.size()) {
			grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_"+roles.get(i).getRoleName()));
			i++;
		}
		i = 0;
		while (i < permissions.size()) {
			grantedAuthorities.add(new SimpleGrantedAuthority(permissions.get(i)));
			i++;
		}
		return grantedAuthorities;
	}

}
class User{

	private final int id;
	private final String Username;
	private final String Email;
	private final String Password;
	private final int isAccountNonExpired;
	private final int isAccountNonLocked;
	private final int isCredentialsNonExpired;
	private final int isEnabled;

	public User(int id, String username, String email, String password, int isAccountNonExpired,
			int isAccountNonLocked, int isCredentialsNonExpired, int isEnabled) {
		super();
		this.id = id;
		Username = username;
		Email = email;
		Password = password;
		this.isAccountNonExpired = isAccountNonExpired;
		this.isAccountNonLocked = isAccountNonLocked;
		this.isCredentialsNonExpired = isCredentialsNonExpired;
		this.isEnabled = isEnabled;
	}

	public int getId() {
		return id;
	}
	public String getUsername() {
		return Username;
	}
	public String getEmail() {
		return Email;
	}
	public String getPassword() {
		return Password;
	}
	public int getIsAccountNonExpired() {
		return isAccountNonExpired;
	}
	public int getIsAccountNonLocked() {
		return isAccountNonLocked;
	}
	public int getIsCredentialsNonExpired() {
		return isCredentialsNonExpired;
	}
	public int getIsEnabled() {
		return isEnabled;
	}

	@Override
	public String toString() {
		return "User [id=" + id + ", Username=" + Username + ", Email=" + Email + ", Password=" + Password + ", isAccountNonExpired=" + isAccountNonExpired + ", isAccountNonLocked=" + isAccountNonLocked
				+ ", isCredentialsNonExpired=" + isCredentialsNonExpired + ", isEnabled=" + isEnabled + "]";
	}
}
class Role{
	private final String RoleName;
	private final String RoleDescription;

	public Role(String roleName, String roleDescription) {
		RoleName = roleName;
		RoleDescription = roleDescription;
	}
	public String getRoleName() {
		return RoleName;
	}
	public String getRoleDescription() {
		return RoleDescription;
	}
}

