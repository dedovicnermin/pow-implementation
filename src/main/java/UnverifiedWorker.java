import com.google.gson.Gson;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.Socket;
import java.security.PublicKey;
import java.util.Map;
import java.util.Objects;
import java.util.Queue;
import java.util.function.Consumer;

/**
 * Responsible for verifying signature of BlockUUID and ensuring we recognize its origin
 */
public class UnverifiedWorker implements Runnable, Consumer<String> {
    final int pid;
    final Socket connection;
    final Map<String, PublicKey> registeredKeys;
    final Queue<BlockRecord> unverifiedBlocks;

    public UnverifiedWorker(final int pid, final Socket connection, final Map<String, PublicKey> registeredKeys, final Queue<BlockRecord> unverifiedBlocks) {
        this.pid = pid;
        this.connection = connection;
        this.registeredKeys = registeredKeys;
        this.unverifiedBlocks = unverifiedBlocks;
    }

    @Override
    public void run() {
        try (
                final ObjectInputStream IN = new ObjectInputStream(connection.getInputStream())
        ) {
            accept((String) IN.readObject());
            Thread.sleep(500L);
        } catch (IOException | ClassNotFoundException | InterruptedException e) {
            System.out.println(this.getClass().getSimpleName() + pid + " has encountered an error : " + e.getMessage());
            e.printStackTrace();
        }
    }

    // consume the json  of UB representation
    @Override
    public void accept(String s) {
        System.out.printf(
                "[%d] %s received unverified block as json - %s%n",
                pid, this.getClass().getSimpleName(), s
        );
        // marshal
        final BlockRecord unverifiedBlock = new Gson().fromJson(s, BlockRecord.class);

        try {
            // legit entity participating in the protocol?
            if (identifiedPublicKey(unverifiedBlock.getMetadata())) {
                System.out.println("Identified public key within process state, pushing UVB onto queue : \n" + unverifiedBlock);
                unverifiedBlocks.add(unverifiedBlock);
            } else {
                System.out.println("Could not verify the signature of this block. Will be thrown out : " + s);
            }
        } catch (Exception e) {
            System.out.println("Error when attempting to verify public key authenticity. ERROR : " + e.getMessage());
            e.printStackTrace();
        }

    }

    private boolean identifiedPublicKey(final BlockMetadata metadata) throws Exception {
        final String data = metadata.getBlockUniqueIdentifier();
        final String signedData = metadata.getSignedUniqueIdentifier();
        final PublicKey publicKey = registeredKeys.get(metadata.getCreatorProcess());
        if (Objects.isNull(publicKey)) return false;
        return Utilities.verifySig(data.getBytes(), publicKey, Utilities.decodeSignedDataIntoBytes(signedData));
    }

}
