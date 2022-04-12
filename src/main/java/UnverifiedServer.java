import java.io.IOException;
import java.net.ServerSocket;
import java.security.PublicKey;
import java.util.Map;
import java.util.Queue;

/**
 * Listens to requests with UB data and metadata from each process
 * Spawns worker responsible for verifying signature of block (ensure we know it's origin)
 * and produces to local priority queue for later processing handled by WorkWorker
 */
public class UnverifiedServer implements Runnable {
    final int pid;
    final int port;
    final Map<String, PublicKey> registeredKeys;        // holds reference to registeredKeys but should not have anything to do with updating its state
    final Queue<BlockRecord> unverifiedBlocks;          // holds reference to queue responsible for bringing the oldest UB to the front (PQ)

    public UnverifiedServer(final int pid, final int port, final Map<String, PublicKey> registeredKeys, final Queue<BlockRecord> unverifiedBlocks) {
        this.pid = pid;
        this.port = port + pid;
        this.registeredKeys = registeredKeys;
        this.unverifiedBlocks = unverifiedBlocks;
        System.out.printf(
                "Creating instance of %s from process [%d] to listen on port [%d]%n",
                this.getClass().getSimpleName(), pid, port + pid
        );
    }

    @Override
    public void run() {
        try (final ServerSocket serverSocket = new ServerSocket(port)) {
            while (true) new UnverifiedWorker(pid, serverSocket.accept(), registeredKeys, unverifiedBlocks).run();
        } catch (IOException e) {
            System.out.println(this.getClass().getSimpleName() + pid + " has encountered an error : " + e.getMessage());
            e.printStackTrace();
        }
    }
}
