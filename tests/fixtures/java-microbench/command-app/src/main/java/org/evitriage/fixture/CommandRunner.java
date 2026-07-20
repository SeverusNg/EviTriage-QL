package org.evitriage.fixture;

import java.io.IOException;

/** Deliberately small data-flow target for the CWE-78 fixture. */
public final class CommandRunner {
    private CommandRunner() {}

    public static int runRequestedCommand(String requestedCommand)
            throws IOException, InterruptedException {
        Process process = new ProcessBuilder("sh", "-c", requestedCommand)
                .inheritIO()
                .start();
        return process.waitFor();
    }

    public static void main(String[] args) throws IOException, InterruptedException {
        if (args.length != 1) {
            throw new IllegalArgumentException("usage: CommandRunner <command>");
        }
        System.exit(runRequestedCommand(args[0]));
    }
}
