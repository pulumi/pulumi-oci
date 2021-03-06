// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Database.outputs.AutonomousContainerDatabaseBackupConfigBackupDestinationDetails;
import java.lang.Integer;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class AutonomousContainerDatabaseBackupConfig {
    /**
     * @return Backup destination details.
     * 
     */
    private final @Nullable AutonomousContainerDatabaseBackupConfigBackupDestinationDetails backupDestinationDetails;
    /**
     * @return Number of days between the current and the earliest point of recoverability covered by automatic backups. This value applies to automatic backups. After a new automatic backup has been created, Oracle removes old automatic backups that are created before the window. When the value is updated, it is applied to all existing automatic backups.
     * 
     */
    private final @Nullable Integer recoveryWindowInDays;

    @CustomType.Constructor
    private AutonomousContainerDatabaseBackupConfig(
        @CustomType.Parameter("backupDestinationDetails") @Nullable AutonomousContainerDatabaseBackupConfigBackupDestinationDetails backupDestinationDetails,
        @CustomType.Parameter("recoveryWindowInDays") @Nullable Integer recoveryWindowInDays) {
        this.backupDestinationDetails = backupDestinationDetails;
        this.recoveryWindowInDays = recoveryWindowInDays;
    }

    /**
     * @return Backup destination details.
     * 
     */
    public Optional<AutonomousContainerDatabaseBackupConfigBackupDestinationDetails> backupDestinationDetails() {
        return Optional.ofNullable(this.backupDestinationDetails);
    }
    /**
     * @return Number of days between the current and the earliest point of recoverability covered by automatic backups. This value applies to automatic backups. After a new automatic backup has been created, Oracle removes old automatic backups that are created before the window. When the value is updated, it is applied to all existing automatic backups.
     * 
     */
    public Optional<Integer> recoveryWindowInDays() {
        return Optional.ofNullable(this.recoveryWindowInDays);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(AutonomousContainerDatabaseBackupConfig defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable AutonomousContainerDatabaseBackupConfigBackupDestinationDetails backupDestinationDetails;
        private @Nullable Integer recoveryWindowInDays;

        public Builder() {
    	      // Empty
        }

        public Builder(AutonomousContainerDatabaseBackupConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.backupDestinationDetails = defaults.backupDestinationDetails;
    	      this.recoveryWindowInDays = defaults.recoveryWindowInDays;
        }

        public Builder backupDestinationDetails(@Nullable AutonomousContainerDatabaseBackupConfigBackupDestinationDetails backupDestinationDetails) {
            this.backupDestinationDetails = backupDestinationDetails;
            return this;
        }
        public Builder recoveryWindowInDays(@Nullable Integer recoveryWindowInDays) {
            this.recoveryWindowInDays = recoveryWindowInDays;
            return this;
        }        public AutonomousContainerDatabaseBackupConfig build() {
            return new AutonomousContainerDatabaseBackupConfig(backupDestinationDetails, recoveryWindowInDays);
        }
    }
}
