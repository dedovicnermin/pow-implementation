import com.google.gson.Gson;

import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

public class VerifiedWorker implements Runnable, Consumer<String> {
    final int pid;
    final Socket connection;
    final Map<Integer, BlockRecord> blockchain;
    final Set<String> verifiedBlockIdentifiers; //uuid

    public VerifiedWorker(int pid, Socket connection, final Map<Integer, BlockRecord> blockchain, final Set<String> verifiedBlockIdentifiers) {
        this.pid = pid;
        this.connection = connection;
        this.blockchain = blockchain;
        this.verifiedBlockIdentifiers = verifiedBlockIdentifiers;
    }

    @Override
    public void run() {
        try (
                final ObjectInputStream IN = new ObjectInputStream(connection.getInputStream());
                final ObjectOutputStream OUT = new ObjectOutputStream(connection.getOutputStream())
        ) {
            accept((String) IN.readObject());               // pass to worker after casting as a json string
        } catch (IOException | ClassNotFoundException e) {
            System.out.println(this.getClass().getSimpleName() + pid + " has encountered an error : " + e.getMessage());
            e.printStackTrace();
        }
    }

    @Override
    public void accept(String s) {
        System.out.printf(
                "[%d] %s received verified block record as json - %s%n",
                pid, this.getClass().getSimpleName(), s
        );
        // included latest verified block into blockchain
        final BlockRecord blockRecord = new Gson().fromJson(s, BlockRecord.class);
        final String blockUniqueIdentifier = blockRecord.getMetadata().getBlockUniqueIdentifier();
        if (!verifiedBlockIdentifiers.contains(blockUniqueIdentifier)) {                                    // final check to ensure we didn't get sent a record we've seen before
            verifiedBlockIdentifiers.add(blockUniqueIdentifier);
            blockchain.putIfAbsent(blockRecord.getMetadata().getBlockId(), blockRecord);
        }

        if (pid == 0) {                     // process 0 is responsible for writing out to filesystem the latest blockchain
            writeJson();
        }
    }

    private void writeJson() {
        try (final FileWriter writer = new FileWriter("BlockchainLedger.json")) {
            final Collection<BlockRecord> values = blockchain.values(); // should still remain sorted as linkedHashMap out of the box
            new Gson().toJson(values, writer);
        } catch (IOException e) {
            System.out.println("Issue with writing out json");
            e.printStackTrace();
        }
    }
}
