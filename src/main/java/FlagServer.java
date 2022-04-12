import java.io.IOException;
import java.net.ServerSocket;
import java.util.concurrent.atomic.AtomicBoolean;

// to be continued. Would like to use as a way to synchronize and to do so via switching state flags
public abstract class FlagServer implements Runnable {
    final int pid;
    final int port;
    final AtomicBoolean flag; // reference to flag we want to trigger

    protected FlagServer(final int pid, final int port, final AtomicBoolean flag) {
        this.pid = pid;
        this.port = port;
        this.flag = flag;
    }

    @Override
    public void run() {
        try (final ServerSocket serverSocket = new ServerSocket(port)) {
            serverSocket.accept();
            System.out.printf("[%d] %s received ping to start the blockchain protocol! Closing server... %n", pid, this.getClass().getSimpleName());
            triggerFlag();
        } catch (IOException e) {
            System.out.println(this.getClass().getSimpleName() + pid + " has encountered an error : " + e.getMessage());
            e.printStackTrace();
        }
    }

    protected void triggerFlag() {
        // allow sub-classes to inherit default behavior
        // will not trigger if flag is already triggered
        flag.compareAndSet(false, true);
    }
}
