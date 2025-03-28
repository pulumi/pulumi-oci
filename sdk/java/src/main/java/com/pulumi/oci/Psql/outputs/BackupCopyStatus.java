// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Psql.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class BackupCopyStatus {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup in the source region
     * 
     */
    private @Nullable String backupId;
    /**
     * @return Region name of the remote region
     * 
     */
    private @Nullable String region;
    /**
     * @return The current state of the backup.
     * 
     */
    private @Nullable String state;
    /**
     * @return A message describing the current state of copy in more detail
     * 
     */
    private @Nullable String stateDetails;

    private BackupCopyStatus() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup in the source region
     * 
     */
    public Optional<String> backupId() {
        return Optional.ofNullable(this.backupId);
    }
    /**
     * @return Region name of the remote region
     * 
     */
    public Optional<String> region() {
        return Optional.ofNullable(this.region);
    }
    /**
     * @return The current state of the backup.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    /**
     * @return A message describing the current state of copy in more detail
     * 
     */
    public Optional<String> stateDetails() {
        return Optional.ofNullable(this.stateDetails);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(BackupCopyStatus defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String backupId;
        private @Nullable String region;
        private @Nullable String state;
        private @Nullable String stateDetails;
        public Builder() {}
        public Builder(BackupCopyStatus defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.backupId = defaults.backupId;
    	      this.region = defaults.region;
    	      this.state = defaults.state;
    	      this.stateDetails = defaults.stateDetails;
        }

        @CustomType.Setter
        public Builder backupId(@Nullable String backupId) {

            this.backupId = backupId;
            return this;
        }
        @CustomType.Setter
        public Builder region(@Nullable String region) {

            this.region = region;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder stateDetails(@Nullable String stateDetails) {

            this.stateDetails = stateDetails;
            return this;
        }
        public BackupCopyStatus build() {
            final var _resultValue = new BackupCopyStatus();
            _resultValue.backupId = backupId;
            _resultValue.region = region;
            _resultValue.state = state;
            _resultValue.stateDetails = stateDetails;
            return _resultValue;
        }
    }
}
