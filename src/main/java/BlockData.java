import java.io.Serializable;

public class BlockData implements Serializable {
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

    public static BlockDataBuilder builder() {
        return new BlockDataBuilder();
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

        public BlockDataBuilder name(String name) {
            this.name = name;
            return this;
        }

        public BlockDataBuilder dob(String dob) {
            this.dob = dob;
            return this;
        }

        public BlockDataBuilder socialSecurity(String socialSecurity) {
            this.socialSecurity = socialSecurity;
            return this;
        }

        public BlockDataBuilder diagnosis(String diagnosis) {
            this.diagnosis = diagnosis;
            return this;
        }

        public BlockDataBuilder treatment(String treatment) {
            this.treatment = treatment;
            return this;
        }

        public BlockDataBuilder prescription(String prescription) {
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
