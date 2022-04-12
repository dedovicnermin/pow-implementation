import java.util.concurrent.atomic.AtomicBoolean;

public class ShutDownListener extends FlagServer {
    protected ShutDownListener(final int pid, final int port, final AtomicBoolean flag) {
        super(pid, port + pid, flag);
        System.out.printf(
                "Creating of %s from process [%d] to listen on port [%d]%n",
                this.getClass().getSimpleName(), pid, port + pid
        );
    }
}
