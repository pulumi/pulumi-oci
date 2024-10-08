// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class AutonomousDatabaseRemoteDisasterRecoveryConfigurationArgs extends com.pulumi.resources.ResourceArgs {

    public static final AutonomousDatabaseRemoteDisasterRecoveryConfigurationArgs Empty = new AutonomousDatabaseRemoteDisasterRecoveryConfigurationArgs();

    /**
     * Indicates the disaster recovery (DR) type of the standby Autonomous Database Serverless instance. Autonomous Data Guard (ADG) DR type provides business critical DR with a faster recovery time objective (RTO) during failover or switchover. Backup-based DR type provides lower cost DR with a slower RTO during failover or switchover.
     * 
     */
    @Import(name="disasterRecoveryType")
    private @Nullable Output<String> disasterRecoveryType;

    /**
     * @return Indicates the disaster recovery (DR) type of the standby Autonomous Database Serverless instance. Autonomous Data Guard (ADG) DR type provides business critical DR with a faster recovery time objective (RTO) during failover or switchover. Backup-based DR type provides lower cost DR with a slower RTO during failover or switchover.
     * 
     */
    public Optional<Output<String>> disasterRecoveryType() {
        return Optional.ofNullable(this.disasterRecoveryType);
    }

    /**
     * If true, 7 days worth of backups are replicated across regions for Cross-Region ADB or Backup-Based DR between Primary and Standby. If false, the backups taken on the Primary are not replicated to the Standby database.
     * 
     */
    @Import(name="isReplicateAutomaticBackups")
    private @Nullable Output<Boolean> isReplicateAutomaticBackups;

    /**
     * @return If true, 7 days worth of backups are replicated across regions for Cross-Region ADB or Backup-Based DR between Primary and Standby. If false, the backups taken on the Primary are not replicated to the Standby database.
     * 
     */
    public Optional<Output<Boolean>> isReplicateAutomaticBackups() {
        return Optional.ofNullable(this.isReplicateAutomaticBackups);
    }

    /**
     * Indicates if user wants to convert to a snapshot standby. For example, true would set a standby database to snapshot standby database. False would set a snapshot standby database back to regular standby database.
     * 
     */
    @Import(name="isSnapshotStandby")
    private @Nullable Output<Boolean> isSnapshotStandby;

    /**
     * @return Indicates if user wants to convert to a snapshot standby. For example, true would set a standby database to snapshot standby database. False would set a snapshot standby database back to regular standby database.
     * 
     */
    public Optional<Output<Boolean>> isSnapshotStandby() {
        return Optional.ofNullable(this.isSnapshotStandby);
    }

    /**
     * Time and date stored as an RFC 3339 formatted timestamp string. For example, 2022-01-01T12:00:00.000Z would set a limit for the snapshot standby to be converted back to a cross-region standby database.
     * 
     */
    @Import(name="timeSnapshotStandbyEnabledTill")
    private @Nullable Output<String> timeSnapshotStandbyEnabledTill;

    /**
     * @return Time and date stored as an RFC 3339 formatted timestamp string. For example, 2022-01-01T12:00:00.000Z would set a limit for the snapshot standby to be converted back to a cross-region standby database.
     * 
     */
    public Optional<Output<String>> timeSnapshotStandbyEnabledTill() {
        return Optional.ofNullable(this.timeSnapshotStandbyEnabledTill);
    }

    private AutonomousDatabaseRemoteDisasterRecoveryConfigurationArgs() {}

    private AutonomousDatabaseRemoteDisasterRecoveryConfigurationArgs(AutonomousDatabaseRemoteDisasterRecoveryConfigurationArgs $) {
        this.disasterRecoveryType = $.disasterRecoveryType;
        this.isReplicateAutomaticBackups = $.isReplicateAutomaticBackups;
        this.isSnapshotStandby = $.isSnapshotStandby;
        this.timeSnapshotStandbyEnabledTill = $.timeSnapshotStandbyEnabledTill;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(AutonomousDatabaseRemoteDisasterRecoveryConfigurationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private AutonomousDatabaseRemoteDisasterRecoveryConfigurationArgs $;

        public Builder() {
            $ = new AutonomousDatabaseRemoteDisasterRecoveryConfigurationArgs();
        }

        public Builder(AutonomousDatabaseRemoteDisasterRecoveryConfigurationArgs defaults) {
            $ = new AutonomousDatabaseRemoteDisasterRecoveryConfigurationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param disasterRecoveryType Indicates the disaster recovery (DR) type of the standby Autonomous Database Serverless instance. Autonomous Data Guard (ADG) DR type provides business critical DR with a faster recovery time objective (RTO) during failover or switchover. Backup-based DR type provides lower cost DR with a slower RTO during failover or switchover.
         * 
         * @return builder
         * 
         */
        public Builder disasterRecoveryType(@Nullable Output<String> disasterRecoveryType) {
            $.disasterRecoveryType = disasterRecoveryType;
            return this;
        }

        /**
         * @param disasterRecoveryType Indicates the disaster recovery (DR) type of the standby Autonomous Database Serverless instance. Autonomous Data Guard (ADG) DR type provides business critical DR with a faster recovery time objective (RTO) during failover or switchover. Backup-based DR type provides lower cost DR with a slower RTO during failover or switchover.
         * 
         * @return builder
         * 
         */
        public Builder disasterRecoveryType(String disasterRecoveryType) {
            return disasterRecoveryType(Output.of(disasterRecoveryType));
        }

        /**
         * @param isReplicateAutomaticBackups If true, 7 days worth of backups are replicated across regions for Cross-Region ADB or Backup-Based DR between Primary and Standby. If false, the backups taken on the Primary are not replicated to the Standby database.
         * 
         * @return builder
         * 
         */
        public Builder isReplicateAutomaticBackups(@Nullable Output<Boolean> isReplicateAutomaticBackups) {
            $.isReplicateAutomaticBackups = isReplicateAutomaticBackups;
            return this;
        }

        /**
         * @param isReplicateAutomaticBackups If true, 7 days worth of backups are replicated across regions for Cross-Region ADB or Backup-Based DR between Primary and Standby. If false, the backups taken on the Primary are not replicated to the Standby database.
         * 
         * @return builder
         * 
         */
        public Builder isReplicateAutomaticBackups(Boolean isReplicateAutomaticBackups) {
            return isReplicateAutomaticBackups(Output.of(isReplicateAutomaticBackups));
        }

        /**
         * @param isSnapshotStandby Indicates if user wants to convert to a snapshot standby. For example, true would set a standby database to snapshot standby database. False would set a snapshot standby database back to regular standby database.
         * 
         * @return builder
         * 
         */
        public Builder isSnapshotStandby(@Nullable Output<Boolean> isSnapshotStandby) {
            $.isSnapshotStandby = isSnapshotStandby;
            return this;
        }

        /**
         * @param isSnapshotStandby Indicates if user wants to convert to a snapshot standby. For example, true would set a standby database to snapshot standby database. False would set a snapshot standby database back to regular standby database.
         * 
         * @return builder
         * 
         */
        public Builder isSnapshotStandby(Boolean isSnapshotStandby) {
            return isSnapshotStandby(Output.of(isSnapshotStandby));
        }

        /**
         * @param timeSnapshotStandbyEnabledTill Time and date stored as an RFC 3339 formatted timestamp string. For example, 2022-01-01T12:00:00.000Z would set a limit for the snapshot standby to be converted back to a cross-region standby database.
         * 
         * @return builder
         * 
         */
        public Builder timeSnapshotStandbyEnabledTill(@Nullable Output<String> timeSnapshotStandbyEnabledTill) {
            $.timeSnapshotStandbyEnabledTill = timeSnapshotStandbyEnabledTill;
            return this;
        }

        /**
         * @param timeSnapshotStandbyEnabledTill Time and date stored as an RFC 3339 formatted timestamp string. For example, 2022-01-01T12:00:00.000Z would set a limit for the snapshot standby to be converted back to a cross-region standby database.
         * 
         * @return builder
         * 
         */
        public Builder timeSnapshotStandbyEnabledTill(String timeSnapshotStandbyEnabledTill) {
            return timeSnapshotStandbyEnabledTill(Output.of(timeSnapshotStandbyEnabledTill));
        }

        public AutonomousDatabaseRemoteDisasterRecoveryConfigurationArgs build() {
            return $;
        }
    }

}
