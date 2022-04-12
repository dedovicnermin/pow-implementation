# Build
FROM maven:3.6.0-jdk-8-slim AS build
COPY ../../src /proofofwork/implementation/src
COPY ../../pom.xml /proofofwork/implementation
RUN mvn -f /proofofwork/implementation/pom.xml clean install package
# Package
FROM openjdk:8-jre-slim
COPY --from=build /proofofwork/implementation/target/pow-implementation-0.0.0-jar-with-dependencies.jar /usr/local/lib/pow.jar
COPY ../../BlockInput0.txt tmp/BlockInput0.txt
ENTRYPOINT ["java", "-jar", "/usr/local/lib/pow.jar"]



