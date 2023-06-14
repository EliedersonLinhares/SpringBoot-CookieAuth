# Java - SpringBoot - Security System with cookies🍪🔒

<img src="https://icongr.am/devicon/java-original.svg?size=128&color=currentColor" alt="java" width="40" height="40"/> </a>
</a> <a href="https://spring.io/" target="_blank"> <img src="https://www.vectorlogo.zone/logos/springio/springio-icon.svg" alt="spring" width="40" height="40"/> </a>
<img src="https://icongr.am/devicon/mysql-original-wordmark.svg?size=128&color=currentColor" alt="java" width="40" height="40"/> </a>

This project was intended to develop on system with security system
where JWT token is put on cookies for security purposes.currently
developed on java 17

v2.0

- Upgrade to java 17
- Upgrade to spring 3.0.7
- Upgrade to jsonwebtoken to 0.11
- Refatoring Some dto's to use java records

v3.0

- Now using link confirmation by email system
- use regex pattern validator for strong password

## FronEnd system

Frontend system was developed on Angular 14

Angular14-CookieAuth - https://github.com/EliedersonLinhares/Angular14-CookieAuth

## Features

<b>`Use cookies to store JWT token`</b> -> Http-only Cookies are used to avoid putting tokens on localstorage.

<b>`Refresh-token`</b> -> To renew tokens for actual user

<b>`Use roles`</b> -> To limit access in endpoints

<b>`Use real database`</b> -> MySql is used but can be change to another like PostgreSQL

<b>`Validators`</b> -> personalized errors messages for authentication,authorization and validation

<b>`Email confimation for register`</b> -> send email after registration with link to endpoint and enable user to access the system

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

## Future plans

- <del>Use email for register confirmation</del> ✅
- Use email for reset password funcionality

## References

Bezkoder - (https://www.bezkoder.com/spring-boot-login-example-mysql/)
