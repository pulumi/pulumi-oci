// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.inputs.AutonomousDatabaseBackupBackupDestinationDetailsArgs;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class AutonomousDatabaseBackupArgs extends com.pulumi.resources.ResourceArgs {

    public static final AutonomousDatabaseBackupArgs Empty = new AutonomousDatabaseBackupArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Database backup.
     * 
     */
    @Import(name="autonomousDatabaseId", required=true)
    private Output<String> autonomousDatabaseId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Database backup.
     * 
     */
    public Output<String> autonomousDatabaseId() {
        return this.autonomousDatabaseId;
    }

    /**
     * Backup destination details
     * 
     */
    @Import(name="backupDestinationDetails")
    private @Nullable Output<AutonomousDatabaseBackupBackupDestinationDetailsArgs> backupDestinationDetails;

    /**
     * @return Backup destination details
     * 
     */
    public Optional<Output<AutonomousDatabaseBackupBackupDestinationDetailsArgs>> backupDestinationDetails() {
        return Optional.ofNullable(this.backupDestinationDetails);
    }

    /**
     * The user-friendly name for the backup. The name does not have to be unique.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return The user-friendly name for the backup. The name does not have to be unique.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * Indicates whether the backup is long-term
     * 
     */
    @Import(name="isLongTermBackup")
    private @Nullable Output<Boolean> isLongTermBackup;

    /**
     * @return Indicates whether the backup is long-term
     * 
     */
    public Optional<Output<Boolean>> isLongTermBackup() {
        return Optional.ofNullable(this.isLongTermBackup);
    }

    /**
     * (Updatable) Retention period, in days, for long-term backups
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="retentionPeriodInDays")
    private @Nullable Output<Integer> retentionPeriodInDays;

    /**
     * @return (Updatable) Retention period, in days, for long-term backups
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<Integer>> retentionPeriodInDays() {
        return Optional.ofNullable(this.retentionPeriodInDays);
    }

    private AutonomousDatabaseBackupArgs() {}

    private AutonomousDatabaseBackupArgs(AutonomousDatabaseBackupArgs $) {
        this.autonomousDatabaseId = $.autonomousDatabaseId;
        this.backupDestinationDetails = $.backupDestinationDetails;
        this.displayName = $.displayName;
        this.isLongTermBackup = $.isLongTermBackup;
        this.retentionPeriodInDays = $.retentionPeriodInDays;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(AutonomousDatabaseBackupArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private AutonomousDatabaseBackupArgs $;

        public Builder() {
            $ = new AutonomousDatabaseBackupArgs();
        }

        public Builder(AutonomousDatabaseBackupArgs defaults) {
            $ = new AutonomousDatabaseBackupArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param autonomousDatabaseId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Database backup.
         * 
         * @return builder
         * 
         */
        public Builder autonomousDatabaseId(Output<String> autonomousDatabaseId) {
            $.autonomousDatabaseId = autonomousDatabaseId;
            return this;
        }

        /**
         * @param autonomousDatabaseId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Database backup.
         * 
         * @return builder
         * 
         */
        public Builder autonomousDatabaseId(String autonomousDatabaseId) {
            return autonomousDatabaseId(Output.of(autonomousDatabaseId));
        }

        /**
         * @param backupDestinationDetails Backup destination details
         * 
         * @return builder
         * 
         */
        public Builder backupDestinationDetails(@Nullable Output<AutonomousDatabaseBackupBackupDestinationDetailsArgs> backupDestinationDetails) {
            $.backupDestinationDetails = backupDestinationDetails;
            return this;
        }

        /**
         * @param backupDestinationDetails Backup destination details
         * 
         * @return builder
         * 
         */
        public Builder backupDestinationDetails(AutonomousDatabaseBackupBackupDestinationDetailsArgs backupDestinationDetails) {
            return backupDestinationDetails(Output.of(backupDestinationDetails));
        }

        /**
         * @param displayName The user-friendly name for the backup. The name does not have to be unique.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName The user-friendly name for the backup. The name does not have to be unique.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param isLongTermBackup Indicates whether the backup is long-term
         * 
         * @return builder
         * 
         */
        public Builder isLongTermBackup(@Nullable Output<Boolean> isLongTermBackup) {
            $.isLongTermBackup = isLongTermBackup;
            return this;
        }

        /**
         * @param isLongTermBackup Indicates whether the backup is long-term
         * 
         * @return builder
         * 
         */
        public Builder isLongTermBackup(Boolean isLongTermBackup) {
            return isLongTermBackup(Output.of(isLongTermBackup));
        }

        /**
         * @param retentionPeriodInDays (Updatable) Retention period, in days, for long-term backups
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder retentionPeriodInDays(@Nullable Output<Integer> retentionPeriodInDays) {
            $.retentionPeriodInDays = retentionPeriodInDays;
            return this;
        }

        /**
         * @param retentionPeriodInDays (Updatable) Retention period, in days, for long-term backups
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder retentionPeriodInDays(Integer retentionPeriodInDays) {
            return retentionPeriodInDays(Output.of(retentionPeriodInDays));
        }

        public AutonomousDatabaseBackupArgs build() {
            if ($.autonomousDatabaseId == null) {
                throw new MissingRequiredPropertyException("AutonomousDatabaseBackupArgs", "autonomousDatabaseId");
            }
            return $;
        }
    }

}
