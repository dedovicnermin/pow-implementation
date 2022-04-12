import java.io.IOException;
import java.net.ServerSocket;
import java.util.Map;
import java.util.Set;

/**
 * Blocks routed to this sink are viewed as verified and solved. Handles updating the state of system for each respective process.
 * Updates set of UUIDs to allow other workers a way of ensuring no one has seen a particular block ,leveraging set collection capabilities
 */
public class VerifiedServer implements Runnable {
    final int pid;
    final int port;
    final Map<Integer, BlockRecord> blockchain;
    final Set<String> verifiedBlockIdentifiers; //uuid

    public VerifiedServer(final int pid, final int port, final Map<Integer, BlockRecord> blockchain, final Set<String> verifiedBlockIdentifiers) {
        this.pid = pid;
        this.port = port + pid;
        this.blockchain = blockchain;
        this.verifiedBlockIdentifiers = verifiedBlockIdentifiers;
        System.out.printf(
                "Creating instance of %s from process [%d] to listen on port [%d]%n",
                this.getClass().getSimpleName(), pid, port + pid
        );
    }

    @Override
    public void run() {
        try (final ServerSocket serverSocket = new ServerSocket(port)) {
            while (!Blockchain.SHUT_DOWN_FLAG.get())
                new VerifiedWorker(pid, serverSocket.accept(), blockchain, verifiedBlockIdentifiers).run();                // Block thread until we receive a block, spawn a worker to handle
        } catch (IOException e) {
            System.out.println(this.getClass().getSimpleName() + pid + " has encountered an error : " + e.getMessage());
            e.printStackTrace();
        }
    }
}
