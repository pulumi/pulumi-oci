// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetAutonomousDatabasesClonesAutonomousDatabaseRemoteDisasterRecoveryConfiguration {
    /**
     * @return Indicates the disaster recovery (DR) type of the Autonomous Database Serverless instance. Autonomous Data Guard (ADG) DR type provides business critical DR with a faster recovery time objective (RTO) during failover or switchover. Backup-based DR type provides lower cost DR with a slower RTO during failover or switchover.
     * 
     */
    private String disasterRecoveryType;
    private Boolean isReplicateAutomaticBackups;
    /**
     * @return Indicates if user wants to convert to a snapshot standby. For example, true would set a standby database to snapshot standby database. False would set a snapshot standby database back to regular standby database.
     * 
     */
    private Boolean isSnapshotStandby;
    /**
     * @return Time and date stored as an RFC 3339 formatted timestamp string. For example, 2022-01-01T12:00:00.000Z would set a limit for the snapshot standby to be converted back to a cross-region standby database.
     * 
     */
    private String timeSnapshotStandbyEnabledTill;

    private GetAutonomousDatabasesClonesAutonomousDatabaseRemoteDisasterRecoveryConfiguration() {}
    /**
     * @return Indicates the disaster recovery (DR) type of the Autonomous Database Serverless instance. Autonomous Data Guard (ADG) DR type provides business critical DR with a faster recovery time objective (RTO) during failover or switchover. Backup-based DR type provides lower cost DR with a slower RTO during failover or switchover.
     * 
     */
    public String disasterRecoveryType() {
        return this.disasterRecoveryType;
    }
    public Boolean isReplicateAutomaticBackups() {
        return this.isReplicateAutomaticBackups;
    }
    /**
     * @return Indicates if user wants to convert to a snapshot standby. For example, true would set a standby database to snapshot standby database. False would set a snapshot standby database back to regular standby database.
     * 
     */
    public Boolean isSnapshotStandby() {
        return this.isSnapshotStandby;
    }
    /**
     * @return Time and date stored as an RFC 3339 formatted timestamp string. For example, 2022-01-01T12:00:00.000Z would set a limit for the snapshot standby to be converted back to a cross-region standby database.
     * 
     */
    public String timeSnapshotStandbyEnabledTill() {
        return this.timeSnapshotStandbyEnabledTill;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAutonomousDatabasesClonesAutonomousDatabaseRemoteDisasterRecoveryConfiguration defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String disasterRecoveryType;
        private Boolean isReplicateAutomaticBackups;
        private Boolean isSnapshotStandby;
        private String timeSnapshotStandbyEnabledTill;
        public Builder() {}
        public Builder(GetAutonomousDatabasesClonesAutonomousDatabaseRemoteDisasterRecoveryConfiguration defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.disasterRecoveryType = defaults.disasterRecoveryType;
    	      this.isReplicateAutomaticBackups = defaults.isReplicateAutomaticBackups;
    	      this.isSnapshotStandby = defaults.isSnapshotStandby;
    	      this.timeSnapshotStandbyEnabledTill = defaults.timeSnapshotStandbyEnabledTill;
        }

        @CustomType.Setter
        public Builder disasterRecoveryType(String disasterRecoveryType) {
            if (disasterRecoveryType == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesClonesAutonomousDatabaseRemoteDisasterRecoveryConfiguration", "disasterRecoveryType");
            }
            this.disasterRecoveryType = disasterRecoveryType;
            return this;
        }
        @CustomType.Setter
        public Builder isReplicateAutomaticBackups(Boolean isReplicateAutomaticBackups) {
            if (isReplicateAutomaticBackups == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesClonesAutonomousDatabaseRemoteDisasterRecoveryConfiguration", "isReplicateAutomaticBackups");
            }
            this.isReplicateAutomaticBackups = isReplicateAutomaticBackups;
            return this;
        }
        @CustomType.Setter
        public Builder isSnapshotStandby(Boolean isSnapshotStandby) {
            if (isSnapshotStandby == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesClonesAutonomousDatabaseRemoteDisasterRecoveryConfiguration", "isSnapshotStandby");
            }
            this.isSnapshotStandby = isSnapshotStandby;
            return this;
        }
        @CustomType.Setter
        public Builder timeSnapshotStandbyEnabledTill(String timeSnapshotStandbyEnabledTill) {
            if (timeSnapshotStandbyEnabledTill == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesClonesAutonomousDatabaseRemoteDisasterRecoveryConfiguration", "timeSnapshotStandbyEnabledTill");
            }
            this.timeSnapshotStandbyEnabledTill = timeSnapshotStandbyEnabledTill;
            return this;
        }
        public GetAutonomousDatabasesClonesAutonomousDatabaseRemoteDisasterRecoveryConfiguration build() {
            final var _resultValue = new GetAutonomousDatabasesClonesAutonomousDatabaseRemoteDisasterRecoveryConfiguration();
            _resultValue.disasterRecoveryType = disasterRecoveryType;
            _resultValue.isReplicateAutomaticBackups = isReplicateAutomaticBackups;
            _resultValue.isSnapshotStandby = isSnapshotStandby;
            _resultValue.timeSnapshotStandbyEnabledTill = timeSnapshotStandbyEnabledTill;
            return _resultValue;
        }
    }
}
