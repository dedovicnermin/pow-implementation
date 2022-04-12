import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

public final class Utilities {
    private Utilities() {
    }

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
    public static String signDataAndEncodeString(final String dataToSign, final PrivateKey privateKey)  {
        // take the data we want to sign and return process signature encoded in string format
        final byte[] signData;
        try {
            signData = signData(dataToSign.getBytes(), privateKey);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            throw new RuntimeException("Unable to sign data and encode data : " + e.getMessage());
        }
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


    public static String encodedToHex(final byte[] bytes) {
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
            int character = (int) (Math.random() * ALPHA_NUMERIC_STRING.length());
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
        return encodedToHex(digest).substring(0, 4);
    }
}
