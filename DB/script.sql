PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS Users (ID INTEGER PRIMARY KEY AUTOINCREMENT,
								Username TEXT type NOT NULL UNIQUE,
								Email TEXT type NOT NULL UNIQUE,
								Password TEXT NOT NULL,
								isAccountNonExpired INTEGER NOT NULL,
								isAccountNonLocked INTEGER NOT NULL,
								isCredentialsNonExpired INTEGER NOT NULL,
								isEnabled INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS Roles (ID INTEGER PRIMARY KEY AUTOINCREMENT,
								RoleName TEXT type NOT NULL UNIQUE,
								RoleDescription TEXT type);

CREATE TABLE IF NOT EXISTS Permissions (ID INTEGER PRIMARY KEY AUTOINCREMENT,
								PermissionName TEXT type NOT NULL UNIQUE);

CREATE TABLE IF NOT EXISTS UsertoRole (UserID INTEGER NOT NULL, 
										RoleID INTEGER NOT NULL,
										PRIMARY KEY (UserID,RoleID),
										FOREIGN KEY (UserID)
											REFERENCES Users (ID)
												ON UPDATE NO ACTION
												ON DELETE CASCADE,
										FOREIGN KEY (RoleID)
											REFERENCES Roles (ID)
												ON UPDATE NO ACTION
												ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS RoletoPermission (RoleID INTEGER NOT NULL, 
										PermissionID INTEGER NOT NULL,
										PRIMARY KEY (RoleID,PermissionID),
										FOREIGN KEY (PermissionID)
											REFERENCES Permissions (ID)
												ON UPDATE NO ACTION
												ON DELETE CASCADE,
										FOREIGN KEY (RoleID)
											REFERENCES Roles (ID)
												ON UPDATE NO ACTION
												ON DELETE CASCADE);

/*Creates a Table to demonstrate SQL Injection Vulnerability*/
CREATE TABLE IF NOT EXISTS Books (ID INTEGER PRIMARY KEY AUTOINCREMENT,
								Title TEXT,
								Author TEXT,
								Year TEXT NOT NULL);

INSERT INTO Books (Title, Author, Year) VALUES ("Title1","Author1","Year1");
INSERT INTO Books (Title, Author, Year) VALUES ("Title2","Author3","Year1");
INSERT INTO Books (Title, Author, Year) VALUES ("Title1","Author1","Year2");
INSERT INTO Books (Title, Author, Year) VALUES ("Title3","Author2","Year2");

/* Password: password1 */
INSERT INTO Users (Username,Email,Password,isAccountNonExpired,isAccountNonLocked,isCredentialsNonExpired,isEnabled) VALUES 
("adam","adam@hotmail.com","$2a$31$L0Ehby1znyKzFMMCsztszee1PM9KxI6xBT7huY/LnC7UvBgNccbkO",1,1,1,1);
/* Password: password2 */
INSERT INTO Users (Username,Email,Password,isAccountNonExpired,isAccountNonLocked,isCredentialsNonExpired,isEnabled) VALUES 
("mary","mary@hotmail.com","$2a$31$J574PyYYDXGFm1..979SNubmkw0SfygRx7kERS2oSJ3XKZgX4WknO",1,1,1,1);
/* Password: password3 */
INSERT INTO Users (Username,Email,Password,isAccountNonExpired,isAccountNonLocked,isCredentialsNonExpired,isEnabled) VALUES 
("john","john@hotmail.com","$2a$31$YYYzhd7t7PYFCN1y8zqD6u1NCKfApfBcq8WOv0fUEKZR/meLMN.5y",1,1,1,1);
/* Password: password4  User To Test the Argon2 Password Encoder*/
INSERT INTO Users (Username,Email,Password,isAccountNonExpired,isAccountNonLocked,isCredentialsNonExpired,isEnabled) VALUES 
("argonTestUser","argontest@hotmail.com","$argon2id$v=19$m=1048576,t=4,p=2$7yAuCPPjvwxj/PlHnVPtsg$oz6iXFWdGFaFjsVYo6ve+X1t5J+rR+3ifbYQwZJdpWw",1,1,1,1);


INSERT INTO Roles (RoleName, RoleDescription) VALUES ("ADMIN","Full Web Access");
INSERT INTO Roles (RoleName, RoleDescription) VALUES ("SQL_EDITOR","Full SQL Access");
INSERT INTO Roles (RoleName, RoleDescription) VALUES ("USER","Read and Update");
INSERT INTO Roles (RoleName, RoleDescription) VALUES ("PRIVILEGED_USER","Read, Write, Create, Update Permissions");


INSERT INTO Permissions (PermissionName) VALUES ("read");
INSERT INTO Permissions (PermissionName) VALUES ("write");
INSERT INTO Permissions (PermissionName) VALUES ("execute");
INSERT INTO Permissions (PermissionName) VALUES ("create");
INSERT INTO Permissions (PermissionName) VALUES ("update");
INSERT INTO Permissions (PermissionName) VALUES ("delete");

INSERT INTO RoletoPermission (RoleID,PermissionID)
SELECT A.ID, B.ID FROM Roles AS A, Permissions AS B
WHERE A.RoleName="ADMIN" AND B.PermissionName="read";
INSERT INTO RoletoPermission (RoleID,PermissionID)
SELECT A.ID, B.ID FROM Roles AS A, Permissions AS B
WHERE A.RoleName="ADMIN" AND B.PermissionName="write";
INSERT INTO RoletoPermission (RoleID,PermissionID)
SELECT A.ID, B.ID FROM Roles AS A, Permissions AS B
WHERE A.RoleName="ADMIN" AND B.PermissionName="execute";


INSERT INTO RoletoPermission (RoleID,PermissionID)
SELECT A.ID, B.ID FROM Roles AS A, Permissions AS B
WHERE A.RoleName="SQL_EDITOR" AND B.PermissionName="create";
INSERT INTO RoletoPermission (RoleID,PermissionID)
SELECT A.ID, B.ID FROM Roles AS A, Permissions AS B
WHERE A.RoleName="SQL_EDITOR" AND B.PermissionName="update";
INSERT INTO RoletoPermission (RoleID,PermissionID)
SELECT A.ID, B.ID FROM Roles AS A, Permissions AS B
WHERE A.RoleName="SQL_EDITOR" AND B.PermissionName="delete";


INSERT INTO RoletoPermission (RoleID,PermissionID)
SELECT A.ID, B.ID FROM Roles AS A, Permissions AS B
WHERE A.RoleName="PRIVILEGED_USER" AND B.PermissionName="read";
INSERT INTO RoletoPermission (RoleID,PermissionID)
SELECT A.ID, B.ID FROM Roles AS A, Permissions AS B
WHERE A.RoleName="PRIVILEGED_USER" AND B.PermissionName="write";
INSERT INTO RoletoPermission (RoleID,PermissionID)
SELECT A.ID, B.ID FROM Roles AS A, Permissions AS B
WHERE A.RoleName="PRIVILEGED_USER" AND B.PermissionName="create";
INSERT INTO RoletoPermission (RoleID,PermissionID)
SELECT A.ID, B.ID FROM Roles AS A, Permissions AS B
WHERE A.RoleName="PRIVILEGED_USER" AND B.PermissionName="update";


INSERT INTO RoletoPermission (RoleID,PermissionID)
SELECT A.ID, B.ID FROM Roles AS A, Permissions AS B
WHERE A.RoleName="USER" AND B.PermissionName="read";
INSERT INTO RoletoPermission (RoleID,PermissionID)
SELECT A.ID, B.ID FROM Roles AS A, Permissions AS B
WHERE A.RoleName="USER" AND B.PermissionName="update";



INSERT INTO UsertoRole (UserID,RoleID)
SELECT A.ID, B.ID FROM Users AS A, Roles AS B
WHERE A.Username="adam" AND B.RoleName="ADMIN";
INSERT INTO UsertoRole (UserID,RoleID)
SELECT A.ID, B.ID FROM Users AS A, Roles AS B
WHERE A.Username="adam" AND B.RoleName="SQL_EDITOR";

INSERT INTO UsertoRole (UserID,RoleID)
SELECT A.ID, B.ID FROM Users AS A, Roles AS B
WHERE A.Username="mary" AND B.RoleName="SQL_EDITOR";

INSERT INTO UsertoRole (UserID,RoleID)
SELECT A.ID, B.ID FROM Users AS A, Roles AS B
WHERE A.Username="john" AND B.RoleName="PRIVILEGED_USER";

/*
GET USER DETAILS
----------------
SELECT * FROM Users WHERE Username="adam";

GET USER ROLES
--------------
SELECT DISTINCT C.RoleName, C.RoleDescription
FROM UsertoRole AS A 
INNER JOIN Users AS B ON A.UserID=B.ID
INNER JOIN Roles AS C ON A.RoleID=C.ID
WHERE B.Username="adam";

GET USER PERMISSIONS
--------------------
SELECT PermissionName
FROM Permissions AS E
INNER JOIN	(
			SELECT DISTINCT C.PermissionID
			FROM RoletoPermission AS C
			INNER JOIN (
						SELECT RoleID 
						FROM UsertoRole as A 
						INNER JOIN Users as B ON A.UserID=B.ID
						WHERE B.Username="john"
						) 
			S on C.RoleID=S.RoleID
			) 
X on E.ID = X.PermissionID;


*/

	
	
	