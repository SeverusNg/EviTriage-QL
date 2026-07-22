// SPDX-License-Identifier: Apache-2.0
package org.evitriage.demo;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public final class UnknownWrapperCase {
    private UnknownWrapperCase() {}

    public interface PathPolicy {
        Path resolve(Path base, String requested) throws IOException;
    }

    public static String readThroughPolicy(Socket socket, Path base, PathPolicy policy)
            throws IOException {
        String requested = new BufferedReader(
                new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8)).readLine();
        Path candidate = policy.resolve(base, requested);
        return Files.readString(candidate, StandardCharsets.UTF_8);
    }
}
