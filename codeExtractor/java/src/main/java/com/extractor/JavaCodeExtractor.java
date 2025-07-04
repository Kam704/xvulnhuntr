package com.codeextractor;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;
import java.util.stream.Stream;

public class JavaCodeExtractor {
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: JavaCodeExtractor <folderPath> <className|methodName>");
            return;
        }

        String folderPath = args[0];
        String name = args[1];

        try {
            Optional<File> matchingFile = findJavaFile(folderPath, name);

            if (matchingFile.isPresent()) {
                String extractedCode = extractCodeBlock(matchingFile.get(), name);
                if (extractedCode != null) {
                    String jsonOutput = formatJson(matchingFile.get().getAbsolutePath(), extractedCode);
                    System.out.println(jsonOutput);
                } else {
                    System.out.println("{\"error\": \"Class or method not found in folder\"}");
                }
            } else {
                System.out.println("{\"error\": \"No matching Java file found\"}");
            }
        } catch (Exception e) {
            System.err.println("Error processing files: " + e.getMessage());
        }
    }

    private static Optional<File> findJavaFile(String folderPath, String name) {
        try (Stream<Path> paths = Files.walk(Paths.get(folderPath))) {
            return paths
                    .filter(Files::isRegularFile)
                    .filter(path -> path.toString().endsWith(".java"))
                    .map(Path::toFile)
                    .filter(file -> containsClassOrMethod(file, name))
                    .findFirst();
        } catch (Exception e) {
            System.err.println("Error searching files: " + e.getMessage());
            return Optional.empty();
        }
    }

    private static boolean containsClassOrMethod(File file, String name) {
        try (FileInputStream in = new FileInputStream(file)) {
            CompilationUnit cu = StaticJavaParser.parse(in);
            return cu.findFirst(ClassOrInterfaceDeclaration.class, c -> c.getNameAsString().equals(name)).isPresent()
                    || cu.findFirst(MethodDeclaration.class, m -> m.getNameAsString().equals(name)).isPresent();
        } catch (Exception e) {
            return false;
        }
    }

    private static String extractCodeBlock(File file, String name) throws Exception {
        FileInputStream in = new FileInputStream(file);
        CompilationUnit cu = StaticJavaParser.parse(in);

        Optional<ClassOrInterfaceDeclaration> classDecl = cu.findFirst(ClassOrInterfaceDeclaration.class,
                c -> c.getNameAsString().equals(name));

        if (classDecl.isPresent()) {
            return classDecl.get().toString();
        }

        Optional<MethodDeclaration> methodDecl = cu.findFirst(MethodDeclaration.class,
                m -> m.getNameAsString().equals(name));

        return methodDecl.map(Object::toString).orElse(null);
    }

    private static String formatJson(String filePath, String sourceCode) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        JsonOutput output = new JsonOutput(filePath, sourceCode);
        return mapper.writeValueAsString(output);
    }

    static class JsonOutput {
        public String filepath;
        public String source;

        public JsonOutput(String filepath, String source) {
            this.filepath = filepath;
            this.source = source;
        }
    }
}
