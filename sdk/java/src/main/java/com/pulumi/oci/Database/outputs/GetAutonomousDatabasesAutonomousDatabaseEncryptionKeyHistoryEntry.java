// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.outputs.GetAutonomousDatabasesAutonomousDatabaseEncryptionKeyHistoryEntryEncryptionKey;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetAutonomousDatabasesAutonomousDatabaseEncryptionKeyHistoryEntry {
    /**
     * @return Details of the Autonomous Database encryption key.
     * 
     */
    private List<GetAutonomousDatabasesAutonomousDatabaseEncryptionKeyHistoryEntryEncryptionKey> encryptionKeys;
    /**
     * @return The date and time the kms key activated.
     * 
     */
    private String timeActivated;

    private GetAutonomousDatabasesAutonomousDatabaseEncryptionKeyHistoryEntry() {}
    /**
     * @return Details of the Autonomous Database encryption key.
     * 
     */
    public List<GetAutonomousDatabasesAutonomousDatabaseEncryptionKeyHistoryEntryEncryptionKey> encryptionKeys() {
        return this.encryptionKeys;
    }
    /**
     * @return The date and time the kms key activated.
     * 
     */
    public String timeActivated() {
        return this.timeActivated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAutonomousDatabasesAutonomousDatabaseEncryptionKeyHistoryEntry defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetAutonomousDatabasesAutonomousDatabaseEncryptionKeyHistoryEntryEncryptionKey> encryptionKeys;
        private String timeActivated;
        public Builder() {}
        public Builder(GetAutonomousDatabasesAutonomousDatabaseEncryptionKeyHistoryEntry defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.encryptionKeys = defaults.encryptionKeys;
    	      this.timeActivated = defaults.timeActivated;
        }

        @CustomType.Setter
        public Builder encryptionKeys(List<GetAutonomousDatabasesAutonomousDatabaseEncryptionKeyHistoryEntryEncryptionKey> encryptionKeys) {
            if (encryptionKeys == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesAutonomousDatabaseEncryptionKeyHistoryEntry", "encryptionKeys");
            }
            this.encryptionKeys = encryptionKeys;
            return this;
        }
        public Builder encryptionKeys(GetAutonomousDatabasesAutonomousDatabaseEncryptionKeyHistoryEntryEncryptionKey... encryptionKeys) {
            return encryptionKeys(List.of(encryptionKeys));
        }
        @CustomType.Setter
        public Builder timeActivated(String timeActivated) {
            if (timeActivated == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesAutonomousDatabaseEncryptionKeyHistoryEntry", "timeActivated");
            }
            this.timeActivated = timeActivated;
            return this;
        }
        public GetAutonomousDatabasesAutonomousDatabaseEncryptionKeyHistoryEntry build() {
            final var _resultValue = new GetAutonomousDatabasesAutonomousDatabaseEncryptionKeyHistoryEntry();
            _resultValue.encryptionKeys = encryptionKeys;
            _resultValue.timeActivated = timeActivated;
            return _resultValue;
        }
    }
}
