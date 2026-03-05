#pragma once

// Starts the HTTP test server on the given port.
// Blocks until the server is stopped (Ctrl+C).
void run_server(int port = 8765);
