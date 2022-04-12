import com.google.gson.Gson;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.Socket;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import java.util.function.Consumer;

// Writes to key map once
public class KeyRegistryWorker implements Runnable, Consumer<String> {
    private final int pid;
    private final Socket connection;
    private final Map<String, PublicKey> publicKeyMap;
    private final Gson gson = new Gson();

    public KeyRegistryWorker(final int pid, final Socket connection, final Map<String, PublicKey> publicKeyMap) {
        this.pid = pid;
        this.connection = connection;
        this.publicKeyMap = publicKeyMap;
    }

    /**
     * We want to consume the public keys sent over to us by each parent routine (including self)
     * So that unverified workers can verify block has been created by a legitimate entity participating
     * in blockchain protocol
     */
    @Override
    public void run() {
        try (
                final ObjectInputStream IN = new ObjectInputStream(connection.getInputStream())
        ) {
            accept((String) IN.readObject());                                                               // expected to be a RegisterKeyRequest with process identifcation data. Delegate work after casting
        } catch (IOException | ClassNotFoundException e) {
            System.out.println(this.getClass().getSimpleName() + pid + " has encountered an error : " + e.getMessage());
            e.printStackTrace();
        }
    }

    @Override
    public void accept(final String s) {
        System.out.printf(
                "[%d] %s received key registry request as json - %s%n",
                pid, this.getClass().getSimpleName(), s
        );
        final RegisterKeyRequest keyRequest = gson.fromJson(s, RegisterKeyRequest.class);
        System.out.printf("[%d] : received key request - %s %n", pid, keyRequest.toString());    // object represenation
        try {
            final PublicKey publicKey = Utilities.decodePublicKeyStringAndMapToKey(keyRequest.getSourcePublicKeyAsString());        // attempt to convert Base64 hex string into original representation : PublicKey
            publicKeyMap.putIfAbsent(keyRequest.getSource(), publicKey);                                                            // if we've already received a key from a process (or a hacker) we will not overwrite the previous one
        } catch (InvalidKeySpecException e) {                                                                                       // when unable to convert to PublicKey (bad format / not encoded / not a PublicKey)
            System.out.println(this.getClass().getSimpleName() + pid + " has encountered an error : " + e.getMessage());
            e.printStackTrace();
        }
    }
}
