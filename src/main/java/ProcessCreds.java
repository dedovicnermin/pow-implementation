import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

// not sent over the wire
public class
ProcessCreds {
    final int pid;
    final String processId;
    final PublicKey publicKey;
    final PrivateKey privateKey;

    public ProcessCreds(final int pid, final KeyPair keyPair) {
        this.pid = pid;
        this.processId = "Process" + pid;
        this.publicKey = keyPair.getPublic();
        this.privateKey = keyPair.getPrivate();
    }

    public int getPid() {
        return pid;
    }

    public String getProcessId() {
        return processId;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }
}
