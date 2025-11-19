# Use Eclipse Temurin JDK 17 as base
FROM eclipse-temurin:17-jdk

# Install Maven
RUN apt-get update && \
    apt-get install -y maven && \
    rm -rf /var/lib/apt/lists/*

ARG MAVEN_CENTRAL_USERNAME
ARG MAVEN_CENTRAL_TOKEN

# Set working directory
RUN mkdir -p /root/.m2 && \
    echo "<settings> \
  <servers> \
    <server> \
      <id>central</id> \
      <username>${MAVEN_CENTRAL_USERNAME}</username> \
      <password>${MAVEN_CENTRAL_TOKEN}</password> \
    </server> \
  </servers> \
  <profiles> \
          <profile> \
              <id>mastercard-base</id> \
              <activation> \
                      <activeByDefault>true</activeByDefault> \
              </activation> \
              <repositories> \
                  <repository> \
                      <snapshots> \
                          <enabled>false</enabled> \
                          <updatePolicy>daily</updatePolicy> \
                      </snapshots> \
                      <id>public</id> \
                      <name>public</name> \
                      <url>https://artifacts.mastercard.int/artifactory/maven-all</url> \
                  </repository> \
                  <repository> \
                      <snapshots> \
                          <enabled>true</enabled> \
                          <updatePolicy>daily</updatePolicy> \
                      </snapshots> \
                      <id>public-snapshots</id> \
                      <name>public-snapshots</name> \
                      <url>https://artifacts.mastercard.int/artifactory/maven-all</url> \
                  </repository> \
              </repositories> \
              <pluginRepositories> \
                  <pluginRepository> \
                      <id>public-snapshots</id> \
                      <url>https://artifacts.mastercard.int/artifactory/maven-all</url> \
                  </pluginRepository> \
                  <pluginRepository> \
                      <id>public</id> \
                      <url>https://artifacts.mastercard.int/artifactory/maven-all</url> \
                  </pluginRepository> \
                  <pluginRepository> \
                      <id>snapshots</id> \
                      <snapshots> \
                          <enabled>true</enabled> \
                      </snapshots> \
                      <url>https://artifacts.mastercard.int/artifactory/maven-all</url> \
                  </pluginRepository> \
              </pluginRepositories> \
          </profile> \
          </profiles> \
          <activeProfiles> \
  \
          <activeProfile>mastercard-base</activeProfile> \
          </activeProfiles> \
</settings>" > /root/.m2/settings.xml

# Set working directory
WORKDIR /app

# Copy project files
COPY . /app

# Default command: build and test
CMD ["mvn", "clean", "package", "-Dmaven.javadoc.skip=false"]
