// SPDX-License-Identifier: Apache-2.0
package org.evitriage.demo;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public final class CanonicalPathCase {
    private CanonicalPathCase() {}

    public static String readContained(Socket socket, Path base) throws IOException {
        String requested = new BufferedReader(
                new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8)).readLine();
        Path normalizedBase = base.toAbsolutePath().normalize();
        Path candidate = normalizedBase.resolve(requested).normalize();
        if (!candidate.startsWith(normalizedBase)) {
            throw new IOException("requested path escapes configured base");
        }
        return Files.readString(candidate, StandardCharsets.UTF_8);
    }
}
