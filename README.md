# Java - SpringBoot - Cookie Auth

This project was intended to develop on system with security system
where JWT token is put on cookies for security purposes.currently
developed on java 17

v2.0
Upgrade to java 17
Upgrade to spring 3.0.6
Upgrade to jsonwebtoken to 0.11

## FronEnd system

Frontend system was developed on Angular 14

Angular14-CookieAuth - https://github.com/EliedersonLinhares/Angular14-CookieAuth

## Features

`Use cookies to store JWT token` -> Http-only Cookies are used to avoid putting tokens on localstorage.

`Refresh-token` -> To renew tokens for actual user

`Use real database` -> MySql is used but can be change to another like PostgreSQL

## EndPoints

Register new User - `POST` - http://localhost:8080/api/auth/signup

Login User with email - `POST` - http://localhost:8080/api/auth/signin

Logout - `POST` - http://localhost:8080/api/auth/signout

Refresh Token - `GET` - http://localhost:8080/api/auth/refreshtoken

User Profile - `GET` - http://localhost:8080/api/auth/user-profile

All users - `GET` - http://localhost:8080/api/auth/users

Other to test roles limitations ->

NO restrictions -`GET`- http://localhost:8080/api/test/all

User,Moderator and Admin -`GET`- http://localhost:8080/api/test/user

Moderator only -`GET`- http://localhost:8080/api/test/mod

Admin only -`GET`- http://localhost:8080/api/test/admin

## Running the application

Its change of IDE do you use

Note: Database already running, where you have to create a new
Schema with name int the application.properties file, my case is `security_example`

## References

Bezkoder - (https://www.bezkoder.com/spring-boot-login-example-mysql/)
