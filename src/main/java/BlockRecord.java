import com.google.gson.GsonBuilder;

import java.io.Serializable;

public class
BlockRecord implements Serializable {
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

    public static BlockRecordBuilder builder() {
        return new BlockRecordBuilder();
    }

    public static class BlockRecordBuilder {
        private BlockMetadata metadata;
        private BlockData data;

        BlockRecordBuilder() {
        }

        public BlockRecordBuilder metadata(BlockMetadata metadata) {
            this.metadata = metadata;
            return this;
        }

        public BlockRecordBuilder data(BlockData data) {
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
