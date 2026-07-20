package org.evitriage.fixture;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/** Deliberately small data-flow target for the CWE-22 fixture. */
public final class PathReader {
    private PathReader() {}

    public static String readRequestedFile(Path documentRoot, String requestedName)
            throws IOException {
        Path requestedPath = documentRoot.resolve(requestedName);
        return Files.readString(requestedPath, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws IOException {
        if (args.length != 2) {
            throw new IllegalArgumentException("usage: PathReader <document-root> <name>");
        }
        System.out.print(readRequestedFile(Path.of(args[0]), args[1]));
    }
}
