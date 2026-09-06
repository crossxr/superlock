# SuperLock Java SDK

Official Java SDK for the SuperLock secrets & config manager.

## Requirements

- Java 17+
- Maven or Gradle

## Installation

### Maven
```xml
<dependency>
    <groupId>dev.superlock</groupId>
    <artifactId>superlock-sdk</artifactId>
    <version>3.0.0</version>
</dependency>
```

### Gradle
```groovy
implementation 'dev.superlock:superlock-sdk:3.0.0'
```

## Usage

```java
import dev.superlock.sdk.SuperLockClient;

SuperLockClient client = SuperLockClient.builder()
    .token(System.getenv("SUPERLOCK_TOKEN"))
    .env(System.getenv("SUPERLOCK_ENV_ID"))
    .build();

String dbPass = client.get("DATABASE_PASSWORD");
String apiKey = client.getOrDefault("THIRD_PARTY_KEY", "fallback");
Map<String, String> all = client.getAll();

// Always close when done (stops background threads)
client.close();
```

## Spring Boot Integration

```java
@Configuration
public class SuperLockConfig {
    @Bean
    public SuperLockClient superLockClient(
        @Value("${superlock.token}") String token,
        @Value("${superlock.env}") String env
    ) {
        return SuperLockClient.builder().token(token).env(env).build();
    }
}

@Service
public class DatabaseService {
    private final SuperLockClient superLock;
    
    public DataSource buildDataSource() {
        return DataSourceBuilder.create()
            .url(superLock.get("DATABASE_URL"))
            .username(superLock.get("DATABASE_USER"))
            .password(superLock.get("DATABASE_PASSWORD"))
            .build();
    }
}
```