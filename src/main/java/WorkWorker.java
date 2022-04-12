import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.Map;
import java.util.Objects;
import java.util.Queue;
import java.util.Set;

/**
 * Responsible for polling the halfway verified blocks (signature verified)
 */
public class WorkWorker implements Runnable {
    private final int pid;
    private final Queue<BlockRecord> unverifiedBlocks;      // Consume blocks produced by our Unverified worker. only poll's but never re-inserts
    private final Set<String> verifiedBlockIdentifiers;     // READ-ONLY
    private final Map<Integer, BlockRecord> blockchain;      //READ-ONLY

    public WorkWorker(int pid, Queue<BlockRecord> unverifiedBlocks, final Set<String> verifiedBlockIdentifiers, final Map<Integer, BlockRecord> blockchain) {
        this.pid = pid;
        this.unverifiedBlocks = unverifiedBlocks;
        this.verifiedBlockIdentifiers = verifiedBlockIdentifiers;
        this.blockchain = blockchain;
    }


    public void run() {
        while (true) {
            final BlockRecord unverifiedBlock = unverifiedBlocks.poll();    // can return null if none are present
            if (Objects.isNull(unverifiedBlock)) continue;                  // if this is the case, continue processing

            final BlockMetadata metadata = unverifiedBlock.getMetadata();
            if (verifiedBlockIdentifiers.contains(metadata.getBlockUniqueIdentifier())) {
                System.out.printf("[%d] : Identifier for block %s already exists in the blockchain. We lost this battle before it began but will continue %n", pid, metadata.getBlockUniqueIdentifier());
                continue;   // no need to attempt to solve
            }


            boolean puzzleSolved = false;
            int workNumber = Integer.MAX_VALUE; // ensure we break out of for loop once solved and immediately check if no one beat process to it
            int size = -1;   // in order to do final verification and proceed with multicast.
            while (!puzzleSolved) {
                for (int i = 0; i < 3 && (workNumber >= 15000); i++) {
                    try {
                        Thread.sleep(1000L); // to mock work behavior. avg time to solve takes 2-3s
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                    size = blockchain.size();
                    final BlockRecord lastVerified = blockchain.get(size - 1);                  // get most recent VB to get the data required to solve puzzle
                    metadata.setPrevWinningHash(lastVerified.getMetadata().getWinningHash());   // update UB with important block metadata and to keep record of proof chain is legit
                    metadata.setBlockId(size);                                                  // new block id > the latest by 1

                    final String randomSeed = Utilities.randomAlphaNumeric(8);             // create a random hex String of 8 characters
                    final String data = unverifiedBlock.getData().asString();                   // concats the data into once string representing block data
                    final String prevWinningHash = metadata.getPrevWinningHash();               // important inorder to solve the puzzle

                    // the three things most important when it comes to verifying a block via hash guessing
                    // prevWinningHash + blockData + randomSeed
                    final String concatData = prevWinningHash + data + randomSeed;
                    final String work = Utilities.hashConcatBlockData(concatData);  // hash concatenated block data
                    workNumber = Integer.parseInt(work, 16);

                    // random seed did not solve the puzzle
                    if (workNumber >= 15000) {
                        System.out.printf("[%d] WorkNumber : %d is not less than 15,000 and did not solve the puzzle %n", pid, workNumber);
                    } else {
                        System.out.printf("[%d] WorkNumber : %d IS less than 15,000 and solves the puzzle. Winning hash : %s %n", pid, workNumber, work);
                        puzzleSolved = true;        // break out of loop
                        metadata.setWinningHash(work);
                        metadata.setWinningRandomSeed(randomSeed);
                        metadata.setVerifyingProcessId("Process" + pid);
                    }
                }

                if (size != blockchain.size() || verifiedBlockIdentifiers.contains(metadata.getBlockUniqueIdentifier())) {
                    System.out.printf("[%d] %s : workValue=%s solved puzzle, but blockchain has been updated %n", pid, this.getClass().getSimpleName(), workNumber);
                }
            }


            if (!verifiedBlockIdentifiers.contains(metadata.getBlockUniqueIdentifier())) {
                System.out.printf("[%d] %s Solved puzzle and ensured we are first! Starting multicast... %n", pid, this.getClass().getSimpleName());
                multicastVerifiedBlock(unverifiedBlock.toString());
            }
        }

    }

    static final int VBC_SERVER_PORT_BASE = 4930;

    private void multicastVerifiedBlock(final String json) {
        for (int i = 0; i < 3; i++) {
            try (
                    final Socket socket = new Socket(Blockchain.LOCALHOST, VBC_SERVER_PORT_BASE + i);
                    final ObjectOutputStream OUT = new ObjectOutputStream(socket.getOutputStream())
            ) {
                System.out.printf("[%d] : Multicasting verified block to block chain port %s %n", pid, json);
                OUT.writeObject(json);
                OUT.flush();
            } catch (IOException e) {
                System.out.printf("[%d] : Something went wrong when trying to multicast verified block %s %n", pid, json);
                e.printStackTrace();
            }
        }
    }

}
