
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.stream.Collectors;


public class Blockchain {
    public static void main(String[] args) throws Exception {
        Utilities.assignProcessId(args, PID);                                                                                   // assign process id's
        PROCESS_CREDENTIALS = new ProcessCreds(PID.get(), Utilities.generateKeyPair(ThreadLocalRandom.current().nextLong()));   // create and store self identification (process+pid && public/private key-pair)
        new Thread(new StartSystemListener(PID.get(),START_SYSTEM_PORT_BASE,SYSTEM_START_FLAG)).start();                        // listens for ping to switch flag signifying start system. Thread is closed upon completing task as it has no other use.
        new Thread(new KeyRegistryServer(PID.get(), PUBLIC_KEY_SERVER_PORT_BASE, REGISTERED_KEYS)).start();                     // start up the key registry listener first as it will soon be getting bombarded with key registry requests from other processes (including self)
        new Thread(new VerifiedServer(PID.get(), VBC_SERVER_PORT_BASE, BLOCKCHAIN, VERIFIED_BLOCK_IDS)).start();                // start up verified block listener and be ready to receive dummy block
        new Thread(new UnverifiedServer(PID.get(), UBC_SERVER_PORT_BASE, REGISTERED_KEYS, UNVERIFIED_BLOCKS)).start();          // start up unverified block listener - responsible for checking signatures and supplying into priorityQueue
        new Thread(new WorkWorker(PID.get(), UNVERIFIED_BLOCKS,VERIFIED_BLOCK_IDS, BLOCKCHAIN)).start();                        // start up work server which consumes from the PQ and competes with other processes to solve the puzzle


        // Process2 is responsible for handling startup work
        // and notifying members of the protocol to begin
        if (PID.get() == 2) {
            multicastDummyBlock();          // starting block 0
            multicastStartSystem();         // everybody should have the dummy stored locally now, send signal to begin
        }

        // condition ensures processes wait until the StartSystemListener
        // receives the green light ping
        while (!SYSTEM_START_FLAG.get()) {
            System.out.println("Waiting for system start flag to be true...");
            Thread.sleep(1000L);
        }

        multicastPublicKey();   // ensure public keys are sent out inorder for processes to verify legitimate members of the protocol

        new Blockchain();       // handles parsing input file, building UBs blocks with the data, and multicasting to protocol members
    }

// ===============================================================================================================

    /**
     * Creates dummy VERIFIED blockchain and multicasts to all processes (including self)
     * Allows for all processes to have base blockchain and perform work off dummy data
     */
    private static void multicastDummyBlock() {
        final BlockRecord dummyBlock = Utilities.createDummyBlock();
        for (int i = 0; i < 3; i++) {
            try (
                    final Socket socket = new Socket(LOCALHOST, VBC_SERVER_PORT_BASE + i);
                    final ObjectOutputStream OUT = new ObjectOutputStream(socket.getOutputStream())
            ) {
                OUT.writeObject(dummyBlock.toString());                 // GSON->JSON
                OUT.flush();
            } catch (IOException e) {
                System.out.println("error inside multicast for dummy block - " + e.getMessage());       // has to be process2
                e.printStackTrace();
            }
        }
    }

    /**
     * Each process must send out it's public key to other members (including self)
     * in the protocol inorder to prove they are a legitimate member of the protocol.
     * Consumers will store the process identification and public key (Map<K,V>) in-memory
     */
    private static void multicastPublicKey() {
        final byte[] encoded = PROCESS_CREDENTIALS.getPublicKey().getEncoded();
        // json of public key string encoded
        final String keyString = Utilities.encodePublicKeyToString(encoded);                                            // Base64 hex string encoding to ensure we do not lose data/representation over the wire
        final String json = new Gson().toJson(new RegisterKeyRequest(PROCESS_CREDENTIALS.getProcessId(), keyString));   // new Gson() might not be necessary, but measure was taken to strengthen thread safety on shared resources

        // multicast to all members of the protocol (including self)
        for (int i = 0; i < 3; i++) {
            try (
                    final Socket socket = new Socket(LOCALHOST, PUBLIC_KEY_SERVER_PORT_BASE + i);
                    final ObjectOutputStream OUT = new ObjectOutputStream(socket.getOutputStream())
            ) {
                OUT.writeObject(json);
                OUT.flush();
            } catch (Exception e) {
                System.out.println("ERROR inside multicast for public keys , pid=" + PID.get());
                e.printStackTrace();
            }
        }
    }

    /**
     * Sends out a PING to each process.
     * Data sent over the wire is not used and hence could be anything other than PING
     * Once receiving processes receives, flips the switch to start system across processes
     */
    private static void multicastStartSystem() {
        for (int i = 0; i < 3; i++) {
            try (
                    final Socket socket = new Socket(LOCALHOST, START_SYSTEM_PORT_BASE + i);
                    final ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream())
            ) {
                objectOutputStream.writeObject("PING");
                objectOutputStream.flush();
            } catch (IOException e) {
                System.out.println("Error occured when attempting to multicast PING to start the system for all  : " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

    // Constructor handles reading respective input file (based on PID) and multicasting each (out of 4) UB to all processes
    // participating in the protocol (including self)
    public Blockchain() throws IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        List<BlockRecord> records = parseFile();
        for (BlockRecord urecord : records) {
            multicastUnverifiedBlocks(urecord);
        }
    }


    // multicast one UB to all processes
    // called 4 times for each process
    private void multicastUnverifiedBlocks(final BlockRecord unverifiedRecordFromFile) {
        for (int i = 0; i < 3; i++) {
            try (
                    final Socket socket = new Socket(LOCALHOST, UBC_SERVER_PORT_BASE + i);
                    final ObjectOutputStream OUT = new ObjectOutputStream(socket.getOutputStream())
            ) {
                final String obj = unverifiedRecordFromFile.toString();     // JSON representation
                OUT.writeObject(obj);
                OUT.flush();
                System.out.printf("[%d] : flushed json on multicasting file record - %s %n", PID.get(), obj);
            } catch (IOException e) {
                System.out.println(this.getClass().getSimpleName() + PID.get() + " has encountered an error in multicasting UB : " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

    /**
     * Create file name based on PID
     * Read file and build UBs with the data
     */
    private List<BlockRecord> parseFile() throws IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        final String fileName = "./BlockInput" + PID.get() + ".txt";
        final List<String> strings = Files.readAllLines(Paths.get(fileName));       // elements separated by new line
        List<BlockRecord> blockRecords = new ArrayList<>();
        for (final String str : strings) {
            final List<String> recordData = Arrays.stream(str.split(" ")).collect(Collectors.toList());
            blockRecords.add(buildRecord(recordData));
        }
        return blockRecords;
    }

    private BlockRecord buildRecord(final List<String> recordData) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        final String blockUniqueIdentifier = UUID.randomUUID().toString();
        return BlockRecord.builder()
                .metadata(
                        BlockMetadata.builder()
                                .blockUniqueIdentifier(blockUniqueIdentifier)
                                .timestamp(LocalDateTime.now().toString())
                                .creatorProcess(PROCESS_CREDENTIALS.getProcessId())
                                .signedUniqueIdentifier(Utilities.signDataAndEncodeString(blockUniqueIdentifier, PROCESS_CREDENTIALS.getPrivateKey()))
                                .build()
                )
                .data(
                        BlockData.builder()
                                .name(recordData.get(0) + " " + recordData.get(1))
                                .dob(recordData.get(2))
                                .socialSecurity(recordData.get(3))
                                .diagnosis(recordData.get(4))
                                .treatment(recordData.get(5))
                                .prescription(recordData.get(6))
                                .build()
                ).build();
    }


    static final int PUBLIC_KEY_SERVER_PORT_BASE = 4710;
    static final int UBC_SERVER_PORT_BASE = 4820;
    static final int VBC_SERVER_PORT_BASE = 4930;
    static final int START_SYSTEM_PORT_BASE = 8080;
    static final AtomicBoolean SYSTEM_START_FLAG = new AtomicBoolean(false);
    static final AtomicInteger PID = new AtomicInteger(0);


    static final Map<Integer, BlockRecord> BLOCKCHAIN = new LinkedHashMap<>(); // only entity that should be modifying this is VerifiedWorker
    static final Set<String> VERIFIED_BLOCK_IDS = new HashSet<>(); // needed by WorkWorker (to query) and VerifiedWorker (to modify)
    static final Map<String, PublicKey> REGISTERED_KEYS = new ConcurrentHashMap<>();    // keys look like ProcessX : x e [0,1,2]
    static final Queue<BlockRecord> UNVERIFIED_BLOCKS = new PriorityBlockingQueue<>(15, Comparator.comparing(
            (final BlockRecord unverifiedRecord) -> LocalDateTime.parse(unverifiedRecord.getMetadata().getTimestamp())      // comparing timestamps of type LocalDateTime. UB's are built with this class but converted to string before going over the wire to avoid deserializing issues (dates)
    ));
    static ProcessCreds PROCESS_CREDENTIALS;            // equivalent to process identification card
    static final String LOCALHOST = "localhost";        // constant leveraged by multicast methods / connecting via socket

}




// ===============================================================================================================


// Does not have to invoke shared variable if it is provided the PID
// Server responsible for accepting/handling register pub key requests
// holds a reference to registeredKeyMap kept locally within object
class KeyRegistryServer implements Runnable {
    final int pid;
    final int port;
    final Map<String, PublicKey> registeredKeys;

    public KeyRegistryServer(final int pid, final int port, final Map<String, PublicKey> registeredKeys) {
        this.port = port + pid;
        this.pid = pid;
        this.registeredKeys = registeredKeys;
        System.out.printf(
                "Creating instance of %s from process [%d] to listen on port [%d]%n",
                this.getClass().getSimpleName(), pid, port+pid
        );

    }
    @Override
    public void run() {
        try (final ServerSocket serverSocket = new ServerSocket(port)) {
            while (true) new KeyRegistryWorker(pid,serverSocket.accept(), registeredKeys).run();                // block until connection arrives, spawn worker to handle behavior
        } catch (IOException e) {
            System.out.println(this.getClass().getSimpleName() + pid + " has encountered an error : " + e.getMessage());
            e.printStackTrace();
        }
    }
}


// Writes to key map once
class KeyRegistryWorker implements Runnable, Consumer<String> {
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
        System.out.printf("[%d] : received key request - %s %n", pid,keyRequest.toString());    // object represenation
        try {
            final PublicKey publicKey = Utilities.decodePublicKeyStringAndMapToKey(keyRequest.getSourcePublicKeyAsString());        // attempt to convert Base64 hex string into original representation : PublicKey
            publicKeyMap.putIfAbsent(keyRequest.getSource(), publicKey);                                                            // if we've already received a key from a process (or a hacker) we will not overwrite the previous one
        } catch (InvalidKeySpecException e) {                                                                                       // when unable to convert to PublicKey (bad format / not encoded / not a PublicKey)
            System.out.println(this.getClass().getSimpleName() + pid + " has encountered an error : " + e.getMessage());
            e.printStackTrace();
        }
    }
}


// ===============================================================================================================



/**
 *  Listens to requests with UB data and metadata from each process
 *  Spawns worker responsible for verifying signature of block (ensure we know it's origin)
 *  and produces to local priority queue for later processing handled by WorkWorker
 */
class UnverifiedServer implements Runnable {
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
                this.getClass().getSimpleName(), pid, port+pid
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




/**
 *  Responsible for verifying signature of BlockUUID and ensuring we recognize its origin
 */
class UnverifiedWorker implements Runnable, Consumer<String> {
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



/**
 * Responsible for polling the halfway verified blocks (signature verified)
 */
class WorkWorker implements Runnable {
    private final int pid;
    private final Queue<BlockRecord> unverifiedBlocks;      // Consume blocks produced by our Unverified worker. only poll's but never re-inserts
    private final Set<String> verifiedBlockIdentifiers;     // READ-ONLY
    private final Map<Integer, BlockRecord> blockchain;      //READ-ONLY

    public WorkWorker(int pid, Queue<BlockRecord> unverifiedBlocks, final Set<String> verifiedBlockIdentifiers, final Map<Integer, BlockRecord> blockchain) throws InterruptedException {
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
                    final String concatData = prevWinningHash+data+randomSeed;
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
                        metadata.setVerifyingProcessId("Process"+String.valueOf(pid));
                    }
                }

                if (size != blockchain.size() || verifiedBlockIdentifiers.contains(metadata.getBlockUniqueIdentifier())) {
                    System.out.printf("[%d] %s : workValue=%s solved puzzle, but blockchain has been updated %n", pid, this.getClass().getSimpleName(), workNumber);
                    continue;
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


// ===============================================================================================================


/**
 * Blocks routed to this sink are viewed as verified and solved. Handles updating the state of system for each respective process.
 * Updates set of UUIDs to allow other workers a way of ensuring no one has seen a particular block ,leveraging set collection capabilities
 */
class VerifiedServer implements Runnable {
    final int pid;
    final int port;
    final Map<Integer, BlockRecord> blockchain;
    final Set<String> verifiedBlockIdentifiers; //uuid
    public VerifiedServer(final int pid, final int port, final Map<Integer, BlockRecord> blockchain, final Set<String> verifiedBlockIdentifiers) {
        this.pid = pid; this.port = port + pid;
        this.blockchain = blockchain;
        this.verifiedBlockIdentifiers = verifiedBlockIdentifiers;
        System.out.printf(
                "Creating instance of %s from process [%d] to listen on port [%d]%n",
                this.getClass().getSimpleName(), pid, port+pid
        );
    }
    @Override
    public void run() {
        try (final ServerSocket serverSocket = new ServerSocket(port)) {
            while (true) new VerifiedWorker(pid, serverSocket.accept(), blockchain, verifiedBlockIdentifiers).run();                // Block thread until we receive a block, spawn a worker to handle
        } catch (IOException e) {
            System.out.println(this.getClass().getSimpleName() + pid + " has encountered an error : " + e.getMessage());
            e.printStackTrace();
        }
    }
}



class VerifiedWorker implements Runnable, Consumer<String> {
    final int pid;
    final Socket connection;
    final Map<Integer, BlockRecord> blockchain;
    final Set<String> verifiedBlockIdentifiers; //uuid

    public VerifiedWorker(int pid, Socket connection, final Map<Integer, BlockRecord> blockchain, final Set<String> verifiedBlockIdentifiers) {
        this.pid = pid; this.connection = connection;
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
            new Gson().toJson(values,writer);
        } catch (IOException e) {
            System.out.println("Issue with writing out json");
            e.printStackTrace();
        }
    }
}



// ===============================================================================================================

class StartSystemListener extends FlagServer {
    protected StartSystemListener(final int pid, final int port, final AtomicBoolean flag) {
        super(pid, port + pid, flag);
        System.out.printf(
                "Creating instance of %s from process [%d] to listen on port [%d]%n",
                this.getClass().getSimpleName(), pid, port+pid
        );
    }
}

// to be continued. Would like to use as a way to synchronize and to do so via switching state flags
abstract class FlagServer implements Runnable {
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
            final Socket ping = serverSocket.accept();
            System.out.printf("[%d] %s received ping to start the blockchain protocol! Closing server... %n", pid, this.getClass().getSimpleName());            // TODO : move above as not appicable to all
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




// ===============================================================================================================




final class Utilities {
    private Utilities() {}
    private static final String ALPHA_NUMERIC_STRING = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static MessageDigest MESSAGE_DIGEST;
    private static KeyFactory RSA;
    static {
        try {
            RSA = KeyFactory.getInstance("RSA");
            MESSAGE_DIGEST = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static void assignProcessId(String[] args, final AtomicInteger pid) {
        if (args.length >= 1) switch (args[0]) {
            case "1":
                pid.set(1);
                break;
            case "2":
                pid.set(2);
                break;
            default:
                pid.set(0);
                break;
        }
    }

    // handles signing a particular string of data which should later be verified by consuming process
    public static String signDataAndEncodeString(final String dataToSign, final PrivateKey privateKey) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        // take the data we want to sign and return process signature encoded in string format
        final byte[] signData = signData(dataToSign.getBytes(), privateKey);
        return encodeBytesToString(signData);
    }

    // Base64 encoded representation in order to maintain the value of sensitive data.
    // even the slightest change will break the priv/pub key relationship
    private static String encodeBytesToString(final byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }


    public static KeyPair generateKeyPair(long seed) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
        rng.setSeed(seed);
        keyGenerator.initialize(2048, rng);
        return (keyGenerator.generateKeyPair());
    }

    // sign with private and verify signature with 1:1 public.
    public static byte[] signData(final byte[] data, final PrivateKey key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initSign(key);
        signer.update(data);
        return (signer.sign());
    }


    // using the public key, verify that the signed version of data is authentic and matches unsigned version of the exact same data (block UUID)
    public static boolean verifySig(final byte[] data, final PublicKey key, final byte[] sig) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initVerify(key);
        signer.update(data);

        return signer.verify(sig);
    }

    // in order to not lose data / representation when sending over the wire
    public static String encodePublicKeyToString(final byte[] encoded) {
        return Base64.getEncoder().encodeToString(encoded);
    }


    public static String encodedToHex(final byte[] bytes){
        StringBuilder hex = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            hex.append(String.format("%02X", b));
        }
        return hex.toString();
    }

    public static BlockRecord createDummyBlock() {
        final String blockUniqueIdentifier = UUID.randomUUID().toString();
        final byte[] digest = MESSAGE_DIGEST.digest("DUMMY".getBytes(StandardCharsets.UTF_8));
        final String winningHash = encodedToHex(digest);
        return BlockRecord.builder()
                .metadata(
                        BlockMetadata.builder()
                                .timestamp(LocalDateTime.now().toString())
                                .blockId(0)
                                .blockUniqueIdentifier(blockUniqueIdentifier)
                                .winningHash(winningHash)
                                .prevWinningHash(winningHash)
                                .winningRandomSeed(randomAlphaNumeric(10))
                                .signedUniqueIdentifier("DUMMY_SIG")
                                .build()
                )
                .data(
                        BlockData.builder()
                                .name("Dummy")
                                .dob("1968.01.21")
                                .diagnosis("cholesterol")
                                .socialSecurity("111-11-1111")
                                .treatment("medicine")
                                .prescription("pills")
                                .build()
                )
                .build();
    }

    // resonsible for creating 1/3 imporatant peices of solving the puzzle - random seed
    public static String randomAlphaNumeric(int count) {
        StringBuilder builder = new StringBuilder();
        while (count-- != 0) {
            int character = (int)(Math.random() * ALPHA_NUMERIC_STRING.length());
            builder.append(ALPHA_NUMERIC_STRING.charAt(character));
        }
        return builder.toString();
    }

    public static PublicKey decodePublicKeyStringAndMapToKey(final String publicKeyString) throws InvalidKeySpecException {
        final byte[] decodedString = Base64.getDecoder().decode(publicKeyString);
        final X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(decodedString);
        return RSA.generatePublic(x509EncodedKeySpec);
    }

    public static byte[] decodeSignedDataIntoBytes(final String data) {
        return Base64.getDecoder().decode(data);
    }

    public static String hashConcatBlockData(final String concatData) {
        final byte[] digest = MESSAGE_DIGEST.digest(concatData.getBytes());
        return encodedToHex(digest).substring(0,4);
    }
}



// POJOs
// ===============================================================================================================

// not sent over the wire
class ProcessCreds {
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

// ===============================================================================================================

class BlockRecord implements Serializable {
    private final BlockMetadata metadata;
    private final BlockData data;

    public BlockRecord(BlockMetadata metadata, BlockData data) {
        this.metadata = metadata;
        this.data = data;
    }

    // toString is Json representation of object
    @Override
    public String toString() {
        return new GsonBuilder()
                .setPrettyPrinting()
                .create()
                .toJson(this);
    }

    public BlockMetadata getMetadata() {
        return metadata;
    }

    public BlockData getData() {
        return data;
    }

    public static BlockRecord.BlockRecordBuilder builder() {
        return new BlockRecord.BlockRecordBuilder();
    }

    public static class BlockRecordBuilder {
        private BlockMetadata metadata;
        private BlockData data;

        BlockRecordBuilder() {}

        public BlockRecord.BlockRecordBuilder metadata(BlockMetadata metadata) {
            this.metadata = metadata;
            return this;
        }

        public BlockRecord.BlockRecordBuilder data(BlockData data) {
            this.data = data;
            return this;
        }

        public BlockRecord build() {
            return new BlockRecord(this.metadata, this.data);
        }

        public String toString() {
            return "BlockRecord.BlockRecordBuilder(metadata=" + this.metadata + ", data=" + this.data + ")";
        }
    }
}


class BlockMetadata implements Serializable {
    private String timestamp;
    private String blockUniqueIdentifier;
    private String signedUniqueIdentifier;
    private String creatorProcess;

    private String verifyingProcessId;

    private Integer blockId;
    private String prevWinningHash;
    private String winningHash;
    private String winningRandomSeed;

    BlockMetadata(String timestamp, String blockUniqueIdentifier, String signedUniqueIdentifier, String creatorProcess, String verifyingProcessId, Integer blockId, String prevWinningHash, String winningHash, String winningRandomSeed) {
        this.timestamp = timestamp;
        this.blockUniqueIdentifier = blockUniqueIdentifier;
        this.signedUniqueIdentifier = signedUniqueIdentifier;
        this.creatorProcess = creatorProcess;
        this.verifyingProcessId = verifyingProcessId;
        this.blockId = blockId;
        this.prevWinningHash = prevWinningHash;
        this.winningHash = winningHash;
        this.winningRandomSeed = winningRandomSeed;
    }

    public static BlockMetadata.BlockMetadataBuilder builder() {
        return new BlockMetadata.BlockMetadataBuilder();
    }

    public String getTimestamp() {
        return this.timestamp;
    }

    public String getBlockUniqueIdentifier() {
        return this.blockUniqueIdentifier;
    }

    public String getSignedUniqueIdentifier() {
        return this.signedUniqueIdentifier;
    }

    public String getCreatorProcess() {
        return this.creatorProcess;
    }

    public String getVerifyingProcessId() {
        return this.verifyingProcessId;
    }

    public Integer getBlockId() {
        return this.blockId;
    }

    public String getPrevWinningHash() {
        return this.prevWinningHash;
    }

    public String getWinningHash() {
        return this.winningHash;
    }

    public String getWinningRandomSeed() {
        return this.winningRandomSeed;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }

    public void setBlockUniqueIdentifier(String blockUniqueIdentifier) {
        this.blockUniqueIdentifier = blockUniqueIdentifier;
    }

    public void setSignedUniqueIdentifier(String signedUniqueIdentifier) {
        this.signedUniqueIdentifier = signedUniqueIdentifier;
    }

    public void setCreatorProcess(String creatorProcess) {
        this.creatorProcess = creatorProcess;
    }

    public void setVerifyingProcessId(String verifyingProcessId) {
        this.verifyingProcessId = verifyingProcessId;
    }

    public void setBlockId(Integer blockId) {
        this.blockId = blockId;
    }

    public void setPrevWinningHash(String prevWinningHash) {
        this.prevWinningHash = prevWinningHash;
    }

    public void setWinningHash(String winningHash) {
        this.winningHash = winningHash;
    }

    public void setWinningRandomSeed(String winningRandomSeed) {
        this.winningRandomSeed = winningRandomSeed;
    }

    public String toString() {
        return "BlockMetadata(timestamp=" + this.getTimestamp() + ", blockUniqueIdentifier=" + this.getBlockUniqueIdentifier() + ", signedUniqueIdentifier=" + this.getSignedUniqueIdentifier() + ", creatorProcess=" + this.getCreatorProcess() + ", verifyingProcessId=" + this.getVerifyingProcessId() + ", blockId=" + this.getBlockId() + ", prevWinningHash=" + this.getPrevWinningHash() + ", winningHash=" + this.getWinningHash() + ", winningRandomSeed=" + this.getWinningRandomSeed() + ")";
    }

    public static class BlockMetadataBuilder {
        private String timestamp;
        private String blockUniqueIdentifier;
        private String signedUniqueIdentifier;
        private String creatorProcess;
        private String verifyingProcessId;
        private Integer blockId;
        private String prevWinningHash;
        private String winningHash;
        private String winningRandomSeed;

        BlockMetadataBuilder() {
        }

        public BlockMetadata.BlockMetadataBuilder timestamp(String timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        public BlockMetadata.BlockMetadataBuilder blockUniqueIdentifier(String blockUniqueIdentifier) {
            this.blockUniqueIdentifier = blockUniqueIdentifier;
            return this;
        }

        public BlockMetadata.BlockMetadataBuilder signedUniqueIdentifier(String signedUniqueIdentifier) {
            this.signedUniqueIdentifier = signedUniqueIdentifier;
            return this;
        }

        public BlockMetadata.BlockMetadataBuilder creatorProcess(String creatorProcess) {
            this.creatorProcess = creatorProcess;
            return this;
        }

        public BlockMetadata.BlockMetadataBuilder verifyingProcessId(String verifyingProcessId) {
            this.verifyingProcessId = verifyingProcessId;
            return this;
        }

        public BlockMetadata.BlockMetadataBuilder blockId(Integer blockId) {
            this.blockId = blockId;
            return this;
        }

        public BlockMetadata.BlockMetadataBuilder prevWinningHash(String prevWinningHash) {
            this.prevWinningHash = prevWinningHash;
            return this;
        }

        public BlockMetadata.BlockMetadataBuilder winningHash(String winningHash) {
            this.winningHash = winningHash;
            return this;
        }

        public BlockMetadata.BlockMetadataBuilder winningRandomSeed(String winningRandomSeed) {
            this.winningRandomSeed = winningRandomSeed;
            return this;
        }

        public BlockMetadata build() {
            return new BlockMetadata(this.timestamp, this.blockUniqueIdentifier, this.signedUniqueIdentifier, this.creatorProcess, this.verifyingProcessId, this.blockId, this.prevWinningHash, this.winningHash, this.winningRandomSeed);
        }

        public String toString() {
            return "BlockMetadata.BlockMetadataBuilder(timestamp=" + this.timestamp + ", blockUniqueIdentifier=" + this.blockUniqueIdentifier + ", signedUniqueIdentifier=" + this.signedUniqueIdentifier + ", creatorProcess=" + this.creatorProcess + ", verifyingProcessId=" + this.verifyingProcessId + ", blockId=" + this.blockId + ", prevWinningHash=" + this.prevWinningHash + ", winningHash=" + this.winningHash + ", winningRandomSeed=" + this.winningRandomSeed + ")";
        }
    }
}



class BlockData implements Serializable {
    // data
    private final String name; // [0] + [1]
    private final String dob;  // [2]
    private final String socialSecurity;    //[3]
    private final String diagnosis; //[4]
    private final String treatment; // 5
    private final String prescription; //6

    public BlockData(String name, String dob, String socialSecurity, String diagnosis, String treatment, String prescription) {
        this.name = name;
        this.dob = dob;
        this.socialSecurity = socialSecurity;
        this.diagnosis = diagnosis;
        this.treatment = treatment;
        this.prescription = prescription;
    }



    public String getName() {
        return name;
    }

    public String getDob() {
        return dob;
    }

    public String getSocialSecurity() {
        return socialSecurity;
    }

    public String getDiagnosis() {
        return diagnosis;
    }

    public String getTreatment() {
        return treatment;
    }

    public String getPrescription() {
        return prescription;
    }

    public String asString() {
        return name + dob + socialSecurity + diagnosis + treatment + prescription;
    }

    public String toString() {
        return "BlockData(name=" + this.getName() + ", dob=" + this.getDob() + ", socialSecurity=" + this.getSocialSecurity() + ", diagnosis=" + this.getDiagnosis() + ", treatment=" + this.getTreatment() + ", prescription=" + this.getPrescription() + ")";
    }

    public static BlockData.BlockDataBuilder builder() {
        return new BlockData.BlockDataBuilder();
    }

    public static class BlockDataBuilder {
        private String name;
        private String dob;
        private String socialSecurity;
        private String diagnosis;
        private String treatment;
        private String prescription;

        public BlockDataBuilder() {
            // does not need
        }

        public BlockData.BlockDataBuilder name(String name) {
            this.name = name;
            return this;
        }

        public BlockData.BlockDataBuilder dob(String dob) {
            this.dob = dob;
            return this;
        }

        public BlockData.BlockDataBuilder socialSecurity(String socialSecurity) {
            this.socialSecurity = socialSecurity;
            return this;
        }

        public BlockData.BlockDataBuilder diagnosis(String diagnosis) {
            this.diagnosis = diagnosis;
            return this;
        }

        public BlockData.BlockDataBuilder treatment(String treatment) {
            this.treatment = treatment;
            return this;
        }

        public BlockData.BlockDataBuilder prescription(String prescription) {
            this.prescription = prescription;
            return this;
        }

        public BlockData build() {
            return new BlockData(this.name, this.dob, this.socialSecurity, this.diagnosis, this.treatment, this.prescription);
        }

        public String toString() {
            return "BlockData.BlockDataBuilder(name=" + this.name + ", dob=" + this.dob + ", socialSecurity=" + this.socialSecurity + ", diagnosis=" + this.diagnosis + ", treatment=" + this.treatment + ", prescription=" + this.prescription + ")";
        }
    }
}


// ===============================================================================================================



class RegisterKeyRequest implements Serializable {
    private final String source; // ie. Process<X>
    private final String sourcePublicKeyAsString;

    public RegisterKeyRequest(final String source, final String sourcePublicKeyAsString) {
        this.source = source;
        this.sourcePublicKeyAsString = sourcePublicKeyAsString;
    }

    public String getSource() {
        return source;
    }

    public String getSourcePublicKeyAsString() {
        return sourcePublicKeyAsString;
    }

    public String toString() {
        return "RegisterKeyRequest(source=" + this.getSource() + ", sourcePublicKeyAsString=" + this.getSourcePublicKeyAsString() + ")";
    }
}

