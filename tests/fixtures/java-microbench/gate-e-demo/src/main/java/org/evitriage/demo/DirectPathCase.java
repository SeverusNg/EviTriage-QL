// SPDX-License-Identifier: Apache-2.0
package org.evitriage.demo;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public final class DirectPathCase {
    private DirectPathCase() {}

    public static String readFromSocket(Socket socket) throws IOException {
        String requested = new BufferedReader(
                new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8)).readLine();
        return Files.readString(Path.of(requested), StandardCharsets.UTF_8);
    }
}
