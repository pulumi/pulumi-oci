// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.outputs.GetAutonomousDatabaseBackupBackupDestinationDetail;
import java.lang.Boolean;
import java.lang.Double;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetAutonomousDatabaseBackupResult {
    private String autonomousDatabaseBackupId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Database.
     * 
     */
    private String autonomousDatabaseId;
    /**
     * @return Backup destination details
     * 
     */
    private List<GetAutonomousDatabaseBackupBackupDestinationDetail> backupDestinationDetails;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return The size of the database in terabytes at the time the backup was taken.
     * 
     */
    private Double databaseSizeInTbs;
    /**
     * @return A valid Oracle Database version for Autonomous Database.
     * 
     */
    private String dbVersion;
    /**
     * @return The user-friendly name for the backup. The name does not have to be unique.
     * 
     */
    private String displayName;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Database backup.
     * 
     */
    private String id;
    /**
     * @return Indicates whether the backup is user-initiated or automatic.
     * 
     */
    private Boolean isAutomatic;
    private Boolean isLongTermBackup;
    /**
     * @return Indicates whether the backup can be used to restore the associated Autonomous Database.
     * 
     */
    private Boolean isRestorable;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the key store of Oracle Vault.
     * 
     */
    private String keyStoreId;
    /**
     * @return The wallet name for Oracle Key Vault.
     * 
     */
    private String keyStoreWalletName;
    /**
     * @return The OCID of the key container that is used as the master encryption key in database transparent data encryption (TDE) operations.
     * 
     */
    private String kmsKeyId;
    /**
     * @return The OCID of the key container version that is used in database transparent data encryption (TDE) operations KMS Key can have multiple key versions. If none is specified, the current key version (latest) of the Key Id is used for the operation. Autonomous Database Serverless does not use key versions, hence is not applicable for Autonomous Database Serverless instances.
     * 
     */
    private String kmsKeyVersionId;
    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return Retention period, in days, for long-term backups
     * 
     */
    private Integer retentionPeriodInDays;
    /**
     * @return The backup size in terrabytes (TB).
     * 
     */
    private Double sizeInTbs;
    /**
     * @return The current state of the backup.
     * 
     */
    private String state;
    /**
     * @return Timestamp until when the backup will be available
     * 
     */
    private String timeAvailableTill;
    /**
     * @return The date and time the backup completed.
     * 
     */
    private String timeEnded;
    /**
     * @return The date and time the backup started.
     * 
     */
    private String timeStarted;
    /**
     * @return The type of backup.
     * 
     */
    private String type;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [vault](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts). This parameter and `secretId` are required for Customer Managed Keys.
     * 
     */
    private String vaultId;

    private GetAutonomousDatabaseBackupResult() {}
    public String autonomousDatabaseBackupId() {
        return this.autonomousDatabaseBackupId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Database.
     * 
     */
    public String autonomousDatabaseId() {
        return this.autonomousDatabaseId;
    }
    /**
     * @return Backup destination details
     * 
     */
    public List<GetAutonomousDatabaseBackupBackupDestinationDetail> backupDestinationDetails() {
        return this.backupDestinationDetails;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The size of the database in terabytes at the time the backup was taken.
     * 
     */
    public Double databaseSizeInTbs() {
        return this.databaseSizeInTbs;
    }
    /**
     * @return A valid Oracle Database version for Autonomous Database.
     * 
     */
    public String dbVersion() {
        return this.dbVersion;
    }
    /**
     * @return The user-friendly name for the backup. The name does not have to be unique.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Database backup.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Indicates whether the backup is user-initiated or automatic.
     * 
     */
    public Boolean isAutomatic() {
        return this.isAutomatic;
    }
    public Boolean isLongTermBackup() {
        return this.isLongTermBackup;
    }
    /**
     * @return Indicates whether the backup can be used to restore the associated Autonomous Database.
     * 
     */
    public Boolean isRestorable() {
        return this.isRestorable;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the key store of Oracle Vault.
     * 
     */
    public String keyStoreId() {
        return this.keyStoreId;
    }
    /**
     * @return The wallet name for Oracle Key Vault.
     * 
     */
    public String keyStoreWalletName() {
        return this.keyStoreWalletName;
    }
    /**
     * @return The OCID of the key container that is used as the master encryption key in database transparent data encryption (TDE) operations.
     * 
     */
    public String kmsKeyId() {
        return this.kmsKeyId;
    }
    /**
     * @return The OCID of the key container version that is used in database transparent data encryption (TDE) operations KMS Key can have multiple key versions. If none is specified, the current key version (latest) of the Key Id is used for the operation. Autonomous Database Serverless does not use key versions, hence is not applicable for Autonomous Database Serverless instances.
     * 
     */
    public String kmsKeyVersionId() {
        return this.kmsKeyVersionId;
    }
    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return Retention period, in days, for long-term backups
     * 
     */
    public Integer retentionPeriodInDays() {
        return this.retentionPeriodInDays;
    }
    /**
     * @return The backup size in terrabytes (TB).
     * 
     */
    public Double sizeInTbs() {
        return this.sizeInTbs;
    }
    /**
     * @return The current state of the backup.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Timestamp until when the backup will be available
     * 
     */
    public String timeAvailableTill() {
        return this.timeAvailableTill;
    }
    /**
     * @return The date and time the backup completed.
     * 
     */
    public String timeEnded() {
        return this.timeEnded;
    }
    /**
     * @return The date and time the backup started.
     * 
     */
    public String timeStarted() {
        return this.timeStarted;
    }
    /**
     * @return The type of backup.
     * 
     */
    public String type() {
        return this.type;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [vault](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts). This parameter and `secretId` are required for Customer Managed Keys.
     * 
     */
    public String vaultId() {
        return this.vaultId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAutonomousDatabaseBackupResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String autonomousDatabaseBackupId;
        private String autonomousDatabaseId;
        private List<GetAutonomousDatabaseBackupBackupDestinationDetail> backupDestinationDetails;
        private String compartmentId;
        private Double databaseSizeInTbs;
        private String dbVersion;
        private String displayName;
        private String id;
        private Boolean isAutomatic;
        private Boolean isLongTermBackup;
        private Boolean isRestorable;
        private String keyStoreId;
        private String keyStoreWalletName;
        private String kmsKeyId;
        private String kmsKeyVersionId;
        private String lifecycleDetails;
        private Integer retentionPeriodInDays;
        private Double sizeInTbs;
        private String state;
        private String timeAvailableTill;
        private String timeEnded;
        private String timeStarted;
        private String type;
        private String vaultId;
        public Builder() {}
        public Builder(GetAutonomousDatabaseBackupResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.autonomousDatabaseBackupId = defaults.autonomousDatabaseBackupId;
    	      this.autonomousDatabaseId = defaults.autonomousDatabaseId;
    	      this.backupDestinationDetails = defaults.backupDestinationDetails;
    	      this.compartmentId = defaults.compartmentId;
    	      this.databaseSizeInTbs = defaults.databaseSizeInTbs;
    	      this.dbVersion = defaults.dbVersion;
    	      this.displayName = defaults.displayName;
    	      this.id = defaults.id;
    	      this.isAutomatic = defaults.isAutomatic;
    	      this.isLongTermBackup = defaults.isLongTermBackup;
    	      this.isRestorable = defaults.isRestorable;
    	      this.keyStoreId = defaults.keyStoreId;
    	      this.keyStoreWalletName = defaults.keyStoreWalletName;
    	      this.kmsKeyId = defaults.kmsKeyId;
    	      this.kmsKeyVersionId = defaults.kmsKeyVersionId;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.retentionPeriodInDays = defaults.retentionPeriodInDays;
    	      this.sizeInTbs = defaults.sizeInTbs;
    	      this.state = defaults.state;
    	      this.timeAvailableTill = defaults.timeAvailableTill;
    	      this.timeEnded = defaults.timeEnded;
    	      this.timeStarted = defaults.timeStarted;
    	      this.type = defaults.type;
    	      this.vaultId = defaults.vaultId;
        }

        @CustomType.Setter
        public Builder autonomousDatabaseBackupId(String autonomousDatabaseBackupId) {
            if (autonomousDatabaseBackupId == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabaseBackupResult", "autonomousDatabaseBackupId");
            }
            this.autonomousDatabaseBackupId = autonomousDatabaseBackupId;
            return this;
        }
        @CustomType.Setter
        public Builder autonomousDatabaseId(String autonomousDatabaseId) {
            if (autonomousDatabaseId == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabaseBackupResult", "autonomousDatabaseId");
            }
            this.autonomousDatabaseId = autonomousDatabaseId;
            return this;
        }
        @CustomType.Setter
        public Builder backupDestinationDetails(List<GetAutonomousDatabaseBackupBackupDestinationDetail> backupDestinationDetails) {
            if (backupDestinationDetails == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabaseBackupResult", "backupDestinationDetails");
            }
            this.backupDestinationDetails = backupDestinationDetails;
            return this;
        }
        public Builder backupDestinationDetails(GetAutonomousDatabaseBackupBackupDestinationDetail... backupDestinationDetails) {
            return backupDestinationDetails(List.of(backupDestinationDetails));
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabaseBackupResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder databaseSizeInTbs(Double databaseSizeInTbs) {
            if (databaseSizeInTbs == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabaseBackupResult", "databaseSizeInTbs");
            }
            this.databaseSizeInTbs = databaseSizeInTbs;
            return this;
        }
        @CustomType.Setter
        public Builder dbVersion(String dbVersion) {
            if (dbVersion == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabaseBackupResult", "dbVersion");
            }
            this.dbVersion = dbVersion;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabaseBackupResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabaseBackupResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder isAutomatic(Boolean isAutomatic) {
            if (isAutomatic == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabaseBackupResult", "isAutomatic");
            }
            this.isAutomatic = isAutomatic;
            return this;
        }
        @CustomType.Setter
        public Builder isLongTermBackup(Boolean isLongTermBackup) {
            if (isLongTermBackup == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabaseBackupResult", "isLongTermBackup");
            }
            this.isLongTermBackup = isLongTermBackup;
            return this;
        }
        @CustomType.Setter
        public Builder isRestorable(Boolean isRestorable) {
            if (isRestorable == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabaseBackupResult", "isRestorable");
            }
            this.isRestorable = isRestorable;
            return this;
        }
        @CustomType.Setter
        public Builder keyStoreId(String keyStoreId) {
            if (keyStoreId == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabaseBackupResult", "keyStoreId");
            }
            this.keyStoreId = keyStoreId;
            return this;
        }
        @CustomType.Setter
        public Builder keyStoreWalletName(String keyStoreWalletName) {
            if (keyStoreWalletName == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabaseBackupResult", "keyStoreWalletName");
            }
            this.keyStoreWalletName = keyStoreWalletName;
            return this;
        }
        @CustomType.Setter
        public Builder kmsKeyId(String kmsKeyId) {
            if (kmsKeyId == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabaseBackupResult", "kmsKeyId");
            }
            this.kmsKeyId = kmsKeyId;
            return this;
        }
        @CustomType.Setter
        public Builder kmsKeyVersionId(String kmsKeyVersionId) {
            if (kmsKeyVersionId == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabaseBackupResult", "kmsKeyVersionId");
            }
            this.kmsKeyVersionId = kmsKeyVersionId;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            if (lifecycleDetails == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabaseBackupResult", "lifecycleDetails");
            }
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder retentionPeriodInDays(Integer retentionPeriodInDays) {
            if (retentionPeriodInDays == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabaseBackupResult", "retentionPeriodInDays");
            }
            this.retentionPeriodInDays = retentionPeriodInDays;
            return this;
        }
        @CustomType.Setter
        public Builder sizeInTbs(Double sizeInTbs) {
            if (sizeInTbs == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabaseBackupResult", "sizeInTbs");
            }
            this.sizeInTbs = sizeInTbs;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabaseBackupResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeAvailableTill(String timeAvailableTill) {
            if (timeAvailableTill == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabaseBackupResult", "timeAvailableTill");
            }
            this.timeAvailableTill = timeAvailableTill;
            return this;
        }
        @CustomType.Setter
        public Builder timeEnded(String timeEnded) {
            if (timeEnded == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabaseBackupResult", "timeEnded");
            }
            this.timeEnded = timeEnded;
            return this;
        }
        @CustomType.Setter
        public Builder timeStarted(String timeStarted) {
            if (timeStarted == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabaseBackupResult", "timeStarted");
            }
            this.timeStarted = timeStarted;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabaseBackupResult", "type");
            }
            this.type = type;
            return this;
        }
        @CustomType.Setter
        public Builder vaultId(String vaultId) {
            if (vaultId == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabaseBackupResult", "vaultId");
            }
            this.vaultId = vaultId;
            return this;
        }
        public GetAutonomousDatabaseBackupResult build() {
            final var _resultValue = new GetAutonomousDatabaseBackupResult();
            _resultValue.autonomousDatabaseBackupId = autonomousDatabaseBackupId;
            _resultValue.autonomousDatabaseId = autonomousDatabaseId;
            _resultValue.backupDestinationDetails = backupDestinationDetails;
            _resultValue.compartmentId = compartmentId;
            _resultValue.databaseSizeInTbs = databaseSizeInTbs;
            _resultValue.dbVersion = dbVersion;
            _resultValue.displayName = displayName;
            _resultValue.id = id;
            _resultValue.isAutomatic = isAutomatic;
            _resultValue.isLongTermBackup = isLongTermBackup;
            _resultValue.isRestorable = isRestorable;
            _resultValue.keyStoreId = keyStoreId;
            _resultValue.keyStoreWalletName = keyStoreWalletName;
            _resultValue.kmsKeyId = kmsKeyId;
            _resultValue.kmsKeyVersionId = kmsKeyVersionId;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.retentionPeriodInDays = retentionPeriodInDays;
            _resultValue.sizeInTbs = sizeInTbs;
            _resultValue.state = state;
            _resultValue.timeAvailableTill = timeAvailableTill;
            _resultValue.timeEnded = timeEnded;
            _resultValue.timeStarted = timeStarted;
            _resultValue.type = type;
            _resultValue.vaultId = vaultId;
            return _resultValue;
        }
    }
}
