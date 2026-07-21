package org.evitriage.fixture;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/** Original query-positive CWE-22 microbenchmark for Gate C-Extra. */
public final class SocketPathReader {
    private SocketPathReader() {}

    public static String readRequestedFile(Path documentRoot, Socket client)
            throws IOException {
        try (BufferedReader requestReader =
                new BufferedReader(
                        new InputStreamReader(
                                client.getInputStream(), StandardCharsets.UTF_8))) {
            String requestedName = requestReader.readLine();
            if (requestedName == null) {
                throw new IOException("client closed before sending a file name");
            }
            Path requestedPath = documentRoot.resolve(requestedName);
            return Files.readString(requestedPath, StandardCharsets.UTF_8);
        }
    }
}
