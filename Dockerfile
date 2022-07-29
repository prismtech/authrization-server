FROM maven:3.6-jdk-11 AS builder

WORKDIR /usr/src/app

#Dependencies
COPY ./pom.xml /usr/src/app/
COPY . /usr/src/app

RUN mvn clean install -DskipTests --no-transfer-progress --fail-never -am

FROM openjdk:11
ARG active_profile=dev

ENV IS_LOCAL_NETWORK="false"
ENV spring_profiles_active=$active_profile

COPY --from=builder /usr/src/app/target/authorization-server-1.0-SNAPSHOT.jar /usr/app/authorization-server-1.0-SNAPSHOT.jar

WORKDIR /usr/app
ENTRYPOINT ["java","-jar","authorization-server-1.0-SNAPSHOT.jar"]
