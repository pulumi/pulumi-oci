// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.RecoveryMod.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.Double;
import java.util.Objects;

@CustomType
public final class GetProtectedDatabasesProtectedDatabaseCollectionItemMetric {
    /**
     * @return The estimated backup storage space, in gigabytes, required to meet the recovery window goal, including foot print and backups for the protected database.
     * 
     */
    private Double backupSpaceEstimateInGbs;
    /**
     * @return Backup storage space, in gigabytes, utilized by the protected database. Oracle charges for the total storage used.
     * 
     */
    private Double backupSpaceUsedInGbs;
    /**
     * @return Number of seconds backups are currently retained for this database.
     * 
     */
    private Double currentRetentionPeriodInSeconds;
    /**
     * @return The estimated space, in gigabytes, consumed by the protected database. The database size is based on the size of the data files in the catalog, and does not include archive logs.
     * 
     */
    private Double dbSizeInGbs;
    /**
     * @return The value TRUE indicates that the protected database is configured to use Real-time data protection, and redo-data is sent from the protected database to Recovery Service. Real-time data protection substantially reduces the window of potential data loss that exists between successive archived redo log backups.
     * 
     */
    private Boolean isRedoLogsEnabled;
    /**
     * @return Number of days of redo/archive to be applied to recover database.
     * 
     */
    private Double minimumRecoveryNeededInDays;
    /**
     * @return The maximum number of days to retain backups for a protected database.
     * 
     */
    private Double retentionPeriodInDays;
    /**
     * @return This is the time window when there is data loss exposure. The point after which recovery is impossible unless additional redo is available.  This is the time we received the last backup or last redo-log shipped.
     * 
     */
    private Double unprotectedWindowInSeconds;

    private GetProtectedDatabasesProtectedDatabaseCollectionItemMetric() {}
    /**
     * @return The estimated backup storage space, in gigabytes, required to meet the recovery window goal, including foot print and backups for the protected database.
     * 
     */
    public Double backupSpaceEstimateInGbs() {
        return this.backupSpaceEstimateInGbs;
    }
    /**
     * @return Backup storage space, in gigabytes, utilized by the protected database. Oracle charges for the total storage used.
     * 
     */
    public Double backupSpaceUsedInGbs() {
        return this.backupSpaceUsedInGbs;
    }
    /**
     * @return Number of seconds backups are currently retained for this database.
     * 
     */
    public Double currentRetentionPeriodInSeconds() {
        return this.currentRetentionPeriodInSeconds;
    }
    /**
     * @return The estimated space, in gigabytes, consumed by the protected database. The database size is based on the size of the data files in the catalog, and does not include archive logs.
     * 
     */
    public Double dbSizeInGbs() {
        return this.dbSizeInGbs;
    }
    /**
     * @return The value TRUE indicates that the protected database is configured to use Real-time data protection, and redo-data is sent from the protected database to Recovery Service. Real-time data protection substantially reduces the window of potential data loss that exists between successive archived redo log backups.
     * 
     */
    public Boolean isRedoLogsEnabled() {
        return this.isRedoLogsEnabled;
    }
    /**
     * @return Number of days of redo/archive to be applied to recover database.
     * 
     */
    public Double minimumRecoveryNeededInDays() {
        return this.minimumRecoveryNeededInDays;
    }
    /**
     * @return The maximum number of days to retain backups for a protected database.
     * 
     */
    public Double retentionPeriodInDays() {
        return this.retentionPeriodInDays;
    }
    /**
     * @return This is the time window when there is data loss exposure. The point after which recovery is impossible unless additional redo is available.  This is the time we received the last backup or last redo-log shipped.
     * 
     */
    public Double unprotectedWindowInSeconds() {
        return this.unprotectedWindowInSeconds;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetProtectedDatabasesProtectedDatabaseCollectionItemMetric defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Double backupSpaceEstimateInGbs;
        private Double backupSpaceUsedInGbs;
        private Double currentRetentionPeriodInSeconds;
        private Double dbSizeInGbs;
        private Boolean isRedoLogsEnabled;
        private Double minimumRecoveryNeededInDays;
        private Double retentionPeriodInDays;
        private Double unprotectedWindowInSeconds;
        public Builder() {}
        public Builder(GetProtectedDatabasesProtectedDatabaseCollectionItemMetric defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.backupSpaceEstimateInGbs = defaults.backupSpaceEstimateInGbs;
    	      this.backupSpaceUsedInGbs = defaults.backupSpaceUsedInGbs;
    	      this.currentRetentionPeriodInSeconds = defaults.currentRetentionPeriodInSeconds;
    	      this.dbSizeInGbs = defaults.dbSizeInGbs;
    	      this.isRedoLogsEnabled = defaults.isRedoLogsEnabled;
    	      this.minimumRecoveryNeededInDays = defaults.minimumRecoveryNeededInDays;
    	      this.retentionPeriodInDays = defaults.retentionPeriodInDays;
    	      this.unprotectedWindowInSeconds = defaults.unprotectedWindowInSeconds;
        }

        @CustomType.Setter
        public Builder backupSpaceEstimateInGbs(Double backupSpaceEstimateInGbs) {
            if (backupSpaceEstimateInGbs == null) {
              throw new MissingRequiredPropertyException("GetProtectedDatabasesProtectedDatabaseCollectionItemMetric", "backupSpaceEstimateInGbs");
            }
            this.backupSpaceEstimateInGbs = backupSpaceEstimateInGbs;
            return this;
        }
        @CustomType.Setter
        public Builder backupSpaceUsedInGbs(Double backupSpaceUsedInGbs) {
            if (backupSpaceUsedInGbs == null) {
              throw new MissingRequiredPropertyException("GetProtectedDatabasesProtectedDatabaseCollectionItemMetric", "backupSpaceUsedInGbs");
            }
            this.backupSpaceUsedInGbs = backupSpaceUsedInGbs;
            return this;
        }
        @CustomType.Setter
        public Builder currentRetentionPeriodInSeconds(Double currentRetentionPeriodInSeconds) {
            if (currentRetentionPeriodInSeconds == null) {
              throw new MissingRequiredPropertyException("GetProtectedDatabasesProtectedDatabaseCollectionItemMetric", "currentRetentionPeriodInSeconds");
            }
            this.currentRetentionPeriodInSeconds = currentRetentionPeriodInSeconds;
            return this;
        }
        @CustomType.Setter
        public Builder dbSizeInGbs(Double dbSizeInGbs) {
            if (dbSizeInGbs == null) {
              throw new MissingRequiredPropertyException("GetProtectedDatabasesProtectedDatabaseCollectionItemMetric", "dbSizeInGbs");
            }
            this.dbSizeInGbs = dbSizeInGbs;
            return this;
        }
        @CustomType.Setter
        public Builder isRedoLogsEnabled(Boolean isRedoLogsEnabled) {
            if (isRedoLogsEnabled == null) {
              throw new MissingRequiredPropertyException("GetProtectedDatabasesProtectedDatabaseCollectionItemMetric", "isRedoLogsEnabled");
            }
            this.isRedoLogsEnabled = isRedoLogsEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder minimumRecoveryNeededInDays(Double minimumRecoveryNeededInDays) {
            if (minimumRecoveryNeededInDays == null) {
              throw new MissingRequiredPropertyException("GetProtectedDatabasesProtectedDatabaseCollectionItemMetric", "minimumRecoveryNeededInDays");
            }
            this.minimumRecoveryNeededInDays = minimumRecoveryNeededInDays;
            return this;
        }
        @CustomType.Setter
        public Builder retentionPeriodInDays(Double retentionPeriodInDays) {
            if (retentionPeriodInDays == null) {
              throw new MissingRequiredPropertyException("GetProtectedDatabasesProtectedDatabaseCollectionItemMetric", "retentionPeriodInDays");
            }
            this.retentionPeriodInDays = retentionPeriodInDays;
            return this;
        }
        @CustomType.Setter
        public Builder unprotectedWindowInSeconds(Double unprotectedWindowInSeconds) {
            if (unprotectedWindowInSeconds == null) {
              throw new MissingRequiredPropertyException("GetProtectedDatabasesProtectedDatabaseCollectionItemMetric", "unprotectedWindowInSeconds");
            }
            this.unprotectedWindowInSeconds = unprotectedWindowInSeconds;
            return this;
        }
        public GetProtectedDatabasesProtectedDatabaseCollectionItemMetric build() {
            final var _resultValue = new GetProtectedDatabasesProtectedDatabaseCollectionItemMetric();
            _resultValue.backupSpaceEstimateInGbs = backupSpaceEstimateInGbs;
            _resultValue.backupSpaceUsedInGbs = backupSpaceUsedInGbs;
            _resultValue.currentRetentionPeriodInSeconds = currentRetentionPeriodInSeconds;
            _resultValue.dbSizeInGbs = dbSizeInGbs;
            _resultValue.isRedoLogsEnabled = isRedoLogsEnabled;
            _resultValue.minimumRecoveryNeededInDays = minimumRecoveryNeededInDays;
            _resultValue.retentionPeriodInDays = retentionPeriodInDays;
            _resultValue.unprotectedWindowInSeconds = unprotectedWindowInSeconds;
            return _resultValue;
        }
    }
}
