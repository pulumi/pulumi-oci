// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.Double;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetAutonomousDatabaseBackupsAutonomousDatabaseBackup {
    /**
     * @return The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    private final String autonomousDatabaseId;
    /**
     * @return The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    private final String compartmentId;
    /**
     * @return The size of the database in terabytes at the time the backup was taken.
     * 
     */
    private final Double databaseSizeInTbs;
    /**
     * @return A filter to return only resources that match the entire display name given. The match is not case sensitive.
     * 
     */
    private final String displayName;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Database backup.
     * 
     */
    private final String id;
    /**
     * @return Indicates whether the backup is user-initiated or automatic.
     * 
     */
    private final Boolean isAutomatic;
    /**
     * @return Indicates whether the backup can be used to restore the associated Autonomous Database.
     * 
     */
    private final Boolean isRestorable;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the key store.
     * 
     */
    private final String keyStoreId;
    /**
     * @return The wallet name for Oracle Key Vault.
     * 
     */
    private final String keyStoreWalletName;
    /**
     * @return The OCID of the key container that is used as the master encryption key in database transparent data encryption (TDE) operations.
     * 
     */
    private final String kmsKeyId;
    /**
     * @return The OCID of the key container version that is used in database transparent data encryption (TDE) operations KMS Key can have multiple key versions. If none is specified, the current key version (latest) of the Key Id is used for the operation.
     * 
     */
    private final String kmsKeyVersionId;
    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    private final String lifecycleDetails;
    /**
     * @return A filter to return only resources that match the given lifecycle state exactly.
     * 
     */
    private final String state;
    /**
     * @return The date and time the backup completed.
     * 
     */
    private final String timeEnded;
    /**
     * @return The date and time the backup started.
     * 
     */
    private final String timeStarted;
    /**
     * @return The type of backup.
     * 
     */
    private final String type;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [vault](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts).
     * 
     */
    private final String vaultId;

    @CustomType.Constructor
    private GetAutonomousDatabaseBackupsAutonomousDatabaseBackup(
        @CustomType.Parameter("autonomousDatabaseId") String autonomousDatabaseId,
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("databaseSizeInTbs") Double databaseSizeInTbs,
        @CustomType.Parameter("displayName") String displayName,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("isAutomatic") Boolean isAutomatic,
        @CustomType.Parameter("isRestorable") Boolean isRestorable,
        @CustomType.Parameter("keyStoreId") String keyStoreId,
        @CustomType.Parameter("keyStoreWalletName") String keyStoreWalletName,
        @CustomType.Parameter("kmsKeyId") String kmsKeyId,
        @CustomType.Parameter("kmsKeyVersionId") String kmsKeyVersionId,
        @CustomType.Parameter("lifecycleDetails") String lifecycleDetails,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("timeEnded") String timeEnded,
        @CustomType.Parameter("timeStarted") String timeStarted,
        @CustomType.Parameter("type") String type,
        @CustomType.Parameter("vaultId") String vaultId) {
        this.autonomousDatabaseId = autonomousDatabaseId;
        this.compartmentId = compartmentId;
        this.databaseSizeInTbs = databaseSizeInTbs;
        this.displayName = displayName;
        this.id = id;
        this.isAutomatic = isAutomatic;
        this.isRestorable = isRestorable;
        this.keyStoreId = keyStoreId;
        this.keyStoreWalletName = keyStoreWalletName;
        this.kmsKeyId = kmsKeyId;
        this.kmsKeyVersionId = kmsKeyVersionId;
        this.lifecycleDetails = lifecycleDetails;
        this.state = state;
        this.timeEnded = timeEnded;
        this.timeStarted = timeStarted;
        this.type = type;
        this.vaultId = vaultId;
    }

    /**
     * @return The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public String autonomousDatabaseId() {
        return this.autonomousDatabaseId;
    }
    /**
     * @return The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
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
     * @return A filter to return only resources that match the entire display name given. The match is not case sensitive.
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
    /**
     * @return Indicates whether the backup can be used to restore the associated Autonomous Database.
     * 
     */
    public Boolean isRestorable() {
        return this.isRestorable;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the key store.
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
     * @return The OCID of the key container version that is used in database transparent data encryption (TDE) operations KMS Key can have multiple key versions. If none is specified, the current key version (latest) of the Key Id is used for the operation.
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
     * @return A filter to return only resources that match the given lifecycle state exactly.
     * 
     */
    public String state() {
        return this.state;
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
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [vault](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts).
     * 
     */
    public String vaultId() {
        return this.vaultId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAutonomousDatabaseBackupsAutonomousDatabaseBackup defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String autonomousDatabaseId;
        private String compartmentId;
        private Double databaseSizeInTbs;
        private String displayName;
        private String id;
        private Boolean isAutomatic;
        private Boolean isRestorable;
        private String keyStoreId;
        private String keyStoreWalletName;
        private String kmsKeyId;
        private String kmsKeyVersionId;
        private String lifecycleDetails;
        private String state;
        private String timeEnded;
        private String timeStarted;
        private String type;
        private String vaultId;

        public Builder() {
    	      // Empty
        }

        public Builder(GetAutonomousDatabaseBackupsAutonomousDatabaseBackup defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.autonomousDatabaseId = defaults.autonomousDatabaseId;
    	      this.compartmentId = defaults.compartmentId;
    	      this.databaseSizeInTbs = defaults.databaseSizeInTbs;
    	      this.displayName = defaults.displayName;
    	      this.id = defaults.id;
    	      this.isAutomatic = defaults.isAutomatic;
    	      this.isRestorable = defaults.isRestorable;
    	      this.keyStoreId = defaults.keyStoreId;
    	      this.keyStoreWalletName = defaults.keyStoreWalletName;
    	      this.kmsKeyId = defaults.kmsKeyId;
    	      this.kmsKeyVersionId = defaults.kmsKeyVersionId;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.state = defaults.state;
    	      this.timeEnded = defaults.timeEnded;
    	      this.timeStarted = defaults.timeStarted;
    	      this.type = defaults.type;
    	      this.vaultId = defaults.vaultId;
        }

        public Builder autonomousDatabaseId(String autonomousDatabaseId) {
            this.autonomousDatabaseId = Objects.requireNonNull(autonomousDatabaseId);
            return this;
        }
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder databaseSizeInTbs(Double databaseSizeInTbs) {
            this.databaseSizeInTbs = Objects.requireNonNull(databaseSizeInTbs);
            return this;
        }
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder isAutomatic(Boolean isAutomatic) {
            this.isAutomatic = Objects.requireNonNull(isAutomatic);
            return this;
        }
        public Builder isRestorable(Boolean isRestorable) {
            this.isRestorable = Objects.requireNonNull(isRestorable);
            return this;
        }
        public Builder keyStoreId(String keyStoreId) {
            this.keyStoreId = Objects.requireNonNull(keyStoreId);
            return this;
        }
        public Builder keyStoreWalletName(String keyStoreWalletName) {
            this.keyStoreWalletName = Objects.requireNonNull(keyStoreWalletName);
            return this;
        }
        public Builder kmsKeyId(String kmsKeyId) {
            this.kmsKeyId = Objects.requireNonNull(kmsKeyId);
            return this;
        }
        public Builder kmsKeyVersionId(String kmsKeyVersionId) {
            this.kmsKeyVersionId = Objects.requireNonNull(kmsKeyVersionId);
            return this;
        }
        public Builder lifecycleDetails(String lifecycleDetails) {
            this.lifecycleDetails = Objects.requireNonNull(lifecycleDetails);
            return this;
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder timeEnded(String timeEnded) {
            this.timeEnded = Objects.requireNonNull(timeEnded);
            return this;
        }
        public Builder timeStarted(String timeStarted) {
            this.timeStarted = Objects.requireNonNull(timeStarted);
            return this;
        }
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        public Builder vaultId(String vaultId) {
            this.vaultId = Objects.requireNonNull(vaultId);
            return this;
        }        public GetAutonomousDatabaseBackupsAutonomousDatabaseBackup build() {
            return new GetAutonomousDatabaseBackupsAutonomousDatabaseBackup(autonomousDatabaseId, compartmentId, databaseSizeInTbs, displayName, id, isAutomatic, isRestorable, keyStoreId, keyStoreWalletName, kmsKeyId, kmsKeyVersionId, lifecycleDetails, state, timeEnded, timeStarted, type, vaultId);
        }
    }
}
