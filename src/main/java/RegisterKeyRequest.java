import java.io.Serializable;

public class RegisterKeyRequest implements Serializable {
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
