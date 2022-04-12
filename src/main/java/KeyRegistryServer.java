import java.io.IOException;
import java.net.ServerSocket;
import java.security.PublicKey;
import java.util.Map;

// Does not have to invoke shared variable if it is provided the PID
// Server responsible for accepting/handling register pub key requests
// holds a reference to registeredKeyMap kept locally within object
public class KeyRegistryServer implements Runnable {
    final int pid;
    final int port;
    final Map<String, PublicKey> registeredKeys;

    public KeyRegistryServer(final int pid, final int port, final Map<String, PublicKey> registeredKeys) {
        this.port = port + pid;
        this.pid = pid;
        this.registeredKeys = registeredKeys;
        System.out.printf(
                "Creating instance of %s from process [%d] to listen on port [%d]%n",
                this.getClass().getSimpleName(), pid, port + pid
        );

    }

    @Override
    public void run() {
        try (final ServerSocket serverSocket = new ServerSocket(port)) {
            while (true)
                new KeyRegistryWorker(pid, serverSocket.accept(), registeredKeys).run();                // block until connection arrives, spawn worker to handle behavior
        } catch (IOException e) {
            System.out.println(this.getClass().getSimpleName() + pid + " has encountered an error : " + e.getMessage());
            e.printStackTrace();
        }
    }
}
