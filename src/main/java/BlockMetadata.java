import java.io.Serializable;

public class BlockMetadata implements Serializable {
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

    public static BlockMetadataBuilder builder() {
        return new BlockMetadataBuilder();
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

        public BlockMetadataBuilder timestamp(String timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        public BlockMetadataBuilder blockUniqueIdentifier(String blockUniqueIdentifier) {
            this.blockUniqueIdentifier = blockUniqueIdentifier;
            return this;
        }

        public BlockMetadataBuilder signedUniqueIdentifier(String signedUniqueIdentifier) {
            this.signedUniqueIdentifier = signedUniqueIdentifier;
            return this;
        }

        public BlockMetadataBuilder creatorProcess(String creatorProcess) {
            this.creatorProcess = creatorProcess;
            return this;
        }

        public BlockMetadataBuilder verifyingProcessId(String verifyingProcessId) {
            this.verifyingProcessId = verifyingProcessId;
            return this;
        }

        public BlockMetadataBuilder blockId(Integer blockId) {
            this.blockId = blockId;
            return this;
        }

        public BlockMetadataBuilder prevWinningHash(String prevWinningHash) {
            this.prevWinningHash = prevWinningHash;
            return this;
        }

        public BlockMetadataBuilder winningHash(String winningHash) {
            this.winningHash = winningHash;
            return this;
        }

        public BlockMetadataBuilder winningRandomSeed(String winningRandomSeed) {
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
