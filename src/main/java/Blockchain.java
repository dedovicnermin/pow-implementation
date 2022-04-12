
import com.google.gson.Gson;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static java.util.Optional.ofNullable;

public class Blockchain {
    public static void main(String[] args) throws Exception {
        Utilities.assignProcessId(args, PID);                                                                                   // assign process id's
        PROCESS_CREDENTIALS = new ProcessCreds(PID.get(), Utilities.generateKeyPair(ThreadLocalRandom.current().nextLong()));   // create and store self identification (process+pid && public/private key-pair)
        new Thread(new StartSystemListener(PID.get(),START_SYSTEM_PORT_BASE,SYSTEM_START_FLAG)).start();                        // listens for ping to switch flag signifying start system. Thread is closed upon completing task as it has no other use.
        new Thread(new KeyRegistryServer(PID.get(), PUBLIC_KEY_SERVER_PORT_BASE, REGISTERED_KEYS)).start();                     // start up the key registry listener first as it will soon be getting bombarded with key registry requests from other processes (including self)
        new Thread(new VerifiedServer(PID.get(), VBC_SERVER_PORT_BASE, BLOCKCHAIN, VERIFIED_BLOCK_IDS)).start();                // start up verified block listener and be ready to receive dummy block
        new Thread(new UnverifiedServer(PID.get(), UBC_SERVER_PORT_BASE, REGISTERED_KEYS, UNVERIFIED_BLOCKS)).start();          // start up unverified block listener - responsible for checking signatures and supplying into priorityQueue
        new Thread(new WorkWorker(PID.get(), UNVERIFIED_BLOCKS,VERIFIED_BLOCK_IDS, BLOCKCHAIN)).start();                        // start up work server which consumes from the PQ and competes with other processes to solve the puzzle
        new Thread(new ShutDownListener(PID.get(), 9092, SHUT_DOWN_FLAG)).start();


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
    public Blockchain() throws IOException {
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
    private List<BlockRecord> parseFile() throws IOException {
        final String fileName = getFileName();
        final InputStream resourceAsStream = ofNullable(
                getClass().getClassLoader().getResourceAsStream(fileName)
        ).orElseThrow(() -> new RuntimeException("ERROR: Could not grab BlockInput resource"));
        final List<BlockRecord> records = new ArrayList<>();
        try (final InputStreamReader streamReader = new InputStreamReader(resourceAsStream, StandardCharsets.UTF_8);
            final BufferedReader reader = new BufferedReader(streamReader)
        ) {
            String line;
            while (Objects.nonNull(line = reader.readLine())) {
                List<String> strings = Arrays.asList(line.split(" "));
                records.add(buildRecord(strings));
            }
        }
        return records;
    }

    /**
     * handles retrieval of input file based on respective processID
     * @return path to file
     */
    private String getFileName() {
        return "BlockInput" + PID.get() + ".txt";
    }

    private BlockRecord buildRecord(final List<String> recordData)  {
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
    static final int SHUT_DOWN_PORT = 9092;
    static final AtomicBoolean SYSTEM_START_FLAG = new AtomicBoolean(false);
    static final AtomicBoolean SHUT_DOWN_FLAG = new AtomicBoolean(false);
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



