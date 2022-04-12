import java.util.concurrent.atomic.AtomicBoolean;

public class StartSystemListener extends FlagServer {
    protected StartSystemListener(final int pid, final int port, final AtomicBoolean flag) {
        super(pid, port + pid, flag);
        System.out.printf(
                "Creating instance of %s from process [%d] to listen on port [%d]%n",
                this.getClass().getSimpleName(), pid, port + pid
        );
    }
}
