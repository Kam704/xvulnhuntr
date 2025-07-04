## Install Java and Maven

```
sudo apt install maven
```

## Build

```
mvn compile
```

## Standalone usage (develop/testing)

```
mvn -q exec:java -Dexec.mainClass="com.codeextractor.JavaCodeExtractor" -Dexec.args="methodName targetSource.java"
```

