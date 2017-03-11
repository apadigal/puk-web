# pmdb-services

## About

As of the date of this writing, this is a **SPRING BOOT** application.  Since this is the PMDB API Services Layer, it is considered 'the' interface to the PMDB Database. 

## Getting Started

In order to work on this application, you will need to download Spring Boot STS (Spring Tool Suite) [LINK](https://spring.io/guides/gs/spring-boot/).  This is an Eclipse based IDE.  Try the "Getting Started Guides" that are available in order to get familiar (if you are not already) with Spring Boot.

### Project Lombok

Lombok is used in this project.  Lombok basically eliminates a lot of 'boilerplate' code.  [LINK](https://projectlombok.org/).  You might need to install it though.  To do so, download the jar file and place it in your STS folder.  Then add these 2 lines after -vmargs in your STS.ini file.

```
-vmargs
. . . .

-javaagent:lombok.jar
-Xbootclasspath/a:lombok.jar
```


