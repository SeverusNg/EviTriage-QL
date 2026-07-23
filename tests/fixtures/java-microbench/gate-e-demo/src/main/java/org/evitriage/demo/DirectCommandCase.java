// SPDX-License-Identifier: Apache-2.0
package org.evitriage.demo;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

public final class DirectCommandCase {
    private DirectCommandCase() {}

    public static Process runFromSocket(Socket socket) throws IOException {
        String requested = new BufferedReader(
                new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8)).readLine();
        return new ProcessBuilder("sh", "-c", requested).start();
    }
}
