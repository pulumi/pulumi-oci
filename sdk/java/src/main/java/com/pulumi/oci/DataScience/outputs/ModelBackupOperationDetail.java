// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ModelBackupOperationDetail {
    /**
     * @return The backup status of the model.
     * 
     */
    private @Nullable String backupState;
    /**
     * @return The backup execution status details of the model.
     * 
     */
    private @Nullable String backupStateDetails;
    /**
     * @return The last backup execution time of the model.
     * 
     */
    private @Nullable String timeLastBackup;

    private ModelBackupOperationDetail() {}
    /**
     * @return The backup status of the model.
     * 
     */
    public Optional<String> backupState() {
        return Optional.ofNullable(this.backupState);
    }
    /**
     * @return The backup execution status details of the model.
     * 
     */
    public Optional<String> backupStateDetails() {
        return Optional.ofNullable(this.backupStateDetails);
    }
    /**
     * @return The last backup execution time of the model.
     * 
     */
    public Optional<String> timeLastBackup() {
        return Optional.ofNullable(this.timeLastBackup);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ModelBackupOperationDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String backupState;
        private @Nullable String backupStateDetails;
        private @Nullable String timeLastBackup;
        public Builder() {}
        public Builder(ModelBackupOperationDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.backupState = defaults.backupState;
    	      this.backupStateDetails = defaults.backupStateDetails;
    	      this.timeLastBackup = defaults.timeLastBackup;
        }

        @CustomType.Setter
        public Builder backupState(@Nullable String backupState) {

            this.backupState = backupState;
            return this;
        }
        @CustomType.Setter
        public Builder backupStateDetails(@Nullable String backupStateDetails) {

            this.backupStateDetails = backupStateDetails;
            return this;
        }
        @CustomType.Setter
        public Builder timeLastBackup(@Nullable String timeLastBackup) {

            this.timeLastBackup = timeLastBackup;
            return this;
        }
        public ModelBackupOperationDetail build() {
            final var _resultValue = new ModelBackupOperationDetail();
            _resultValue.backupState = backupState;
            _resultValue.backupStateDetails = backupStateDetails;
            _resultValue.timeLastBackup = timeLastBackup;
            return _resultValue;
        }
    }
}
