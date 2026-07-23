// SPDX-License-Identifier: Apache-2.0
package org.evitriage.demo;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Set;

public final class AllowlistCommandCase {
    private static final Set<String> ALLOWED_COMMANDS = Set.of("status", "version");

    private AllowlistCommandCase() {}

    public static Process runAllowedFromSocket(Socket socket) throws IOException {
        String requested = new BufferedReader(
                new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8)).readLine();
        if (!ALLOWED_COMMANDS.contains(requested)) {
            throw new IOException("command is not allowlisted");
        }
        return new ProcessBuilder(requested).start();
    }
}
