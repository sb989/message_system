DROP DATABASE IF EXISTS message_system;
CREATE DATABASE message_system;
USE message_system;

CREATE TABLE user_info(

	Username VARCHAR(512) NOT NULL,
	Pword	BLOB NOT NULL,
    Salt BLOB NOT NULL,
	LoggedIn VARCHAR(8) NOT NULL,
	PublicKey VARCHAR(40),
    index(Username),
    PRIMARY KEY(Username)
)ENGINE=INNODB;

