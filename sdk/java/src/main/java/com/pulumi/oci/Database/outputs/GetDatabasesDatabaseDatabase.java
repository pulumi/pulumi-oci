// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.outputs.GetDatabasesDatabaseDatabaseDbBackupConfig;
import com.pulumi.oci.Database.outputs.GetDatabasesDatabaseDatabaseEncryptionKeyLocationDetail;
import com.pulumi.oci.Database.outputs.GetDatabasesDatabaseDatabaseSourceEncryptionKeyLocationDetail;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetDatabasesDatabaseDatabase {
    private String adminPassword;
    private String backupId;
    private String backupTdePassword;
    /**
     * @return The character set for the database.
     * 
     */
    private String characterSet;
    private String databaseAdminPassword;
    /**
     * @return The database software image [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
     * 
     */
    private String databaseSoftwareImageId;
    /**
     * @return Backup Options To use any of the API operations, you must be authorized in an IAM policy. If you&#39;re not authorized, talk to an administrator. If you&#39;re an administrator who needs to write policies to give users access, see [Getting Started with Policies](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/policygetstarted.htm).
     * 
     */
    private List<GetDatabasesDatabaseDatabaseDbBackupConfig> dbBackupConfigs;
    /**
     * @return A filter to return only resources that match the entire database name given. The match is not case sensitive.
     * 
     */
    private String dbName;
    /**
     * @return A system-generated name for the database to ensure uniqueness within an Oracle Data Guard group (a primary database and its standby databases). The unique name cannot be changed.
     * 
     */
    private String dbUniqueName;
    /**
     * @return **Deprecated.** The dbWorkload field has been deprecated for Exadata Database Service on Dedicated Infrastructure, Exadata Database Service on Cloud{@literal @}Customer, and Base Database Service. Support for this attribute will end in November 2023. You may choose to update your custom scripts to exclude the dbWorkload attribute. After November 2023 if you pass a value to the dbWorkload attribute, it will be ignored.
     * 
     */
    private String dbWorkload;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return Types of providers supported for managing database encryption keys
     * 
     */
    private List<GetDatabasesDatabaseDatabaseEncryptionKeyLocationDetail> encryptionKeyLocationDetails;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return True if active Data Guard is enabled.
     * 
     */
    private Boolean isActiveDataGuardEnabled;
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
     * @return The national character set for the database.
     * 
     */
    private String ncharacterSet;
    /**
     * @return The name of the pluggable database. The name must begin with an alphabetic character and can contain a maximum of thirty alphanumeric characters. Special characters are not permitted. Pluggable database should not be same as database name.
     * 
     */
    private String pdbName;
    private List<String> pluggableDatabases;
    /**
     * @return The protection mode of this Data Guard. For more information, see [Oracle Data Guard Protection Modes](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-protection-modes.htm#SBYDB02000) in the Oracle Data Guard documentation.
     * 
     */
    private String protectionMode;
    /**
     * @return Specifies a prefix for the `Oracle SID` of the database to be created.
     * 
     */
    private String sidPrefix;
    private String sourceDatabaseId;
    private List<GetDatabasesDatabaseDatabaseSourceEncryptionKeyLocationDetail> sourceEncryptionKeyLocationDetails;
    private String sourceTdeWalletPassword;
    private String tdeWalletPassword;
    /**
     * @return The redo transport type to use for this Data Guard association.  Valid values depend on the specified `protectionMode`:
     * * MAXIMUM_AVAILABILITY - SYNC or FASTSYNC
     * * MAXIMUM_PERFORMANCE - ASYNC
     * * MAXIMUM_PROTECTION - SYNC
     * 
     */
    private String transportType;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [vault](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts). This parameter and `secretId` are required for Customer Managed Keys.
     * 
     */
    private String vaultId;

    private GetDatabasesDatabaseDatabase() {}
    public String adminPassword() {
        return this.adminPassword;
    }
    public String backupId() {
        return this.backupId;
    }
    public String backupTdePassword() {
        return this.backupTdePassword;
    }
    /**
     * @return The character set for the database.
     * 
     */
    public String characterSet() {
        return this.characterSet;
    }
    public String databaseAdminPassword() {
        return this.databaseAdminPassword;
    }
    /**
     * @return The database software image [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
     * 
     */
    public String databaseSoftwareImageId() {
        return this.databaseSoftwareImageId;
    }
    /**
     * @return Backup Options To use any of the API operations, you must be authorized in an IAM policy. If you&#39;re not authorized, talk to an administrator. If you&#39;re an administrator who needs to write policies to give users access, see [Getting Started with Policies](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/policygetstarted.htm).
     * 
     */
    public List<GetDatabasesDatabaseDatabaseDbBackupConfig> dbBackupConfigs() {
        return this.dbBackupConfigs;
    }
    /**
     * @return A filter to return only resources that match the entire database name given. The match is not case sensitive.
     * 
     */
    public String dbName() {
        return this.dbName;
    }
    /**
     * @return A system-generated name for the database to ensure uniqueness within an Oracle Data Guard group (a primary database and its standby databases). The unique name cannot be changed.
     * 
     */
    public String dbUniqueName() {
        return this.dbUniqueName;
    }
    /**
     * @return **Deprecated.** The dbWorkload field has been deprecated for Exadata Database Service on Dedicated Infrastructure, Exadata Database Service on Cloud{@literal @}Customer, and Base Database Service. Support for this attribute will end in November 2023. You may choose to update your custom scripts to exclude the dbWorkload attribute. After November 2023 if you pass a value to the dbWorkload attribute, it will be ignored.
     * 
     */
    public String dbWorkload() {
        return this.dbWorkload;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return Types of providers supported for managing database encryption keys
     * 
     */
    public List<GetDatabasesDatabaseDatabaseEncryptionKeyLocationDetail> encryptionKeyLocationDetails() {
        return this.encryptionKeyLocationDetails;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return True if active Data Guard is enabled.
     * 
     */
    public Boolean isActiveDataGuardEnabled() {
        return this.isActiveDataGuardEnabled;
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
     * @return The national character set for the database.
     * 
     */
    public String ncharacterSet() {
        return this.ncharacterSet;
    }
    /**
     * @return The name of the pluggable database. The name must begin with an alphabetic character and can contain a maximum of thirty alphanumeric characters. Special characters are not permitted. Pluggable database should not be same as database name.
     * 
     */
    public String pdbName() {
        return this.pdbName;
    }
    public List<String> pluggableDatabases() {
        return this.pluggableDatabases;
    }
    /**
     * @return The protection mode of this Data Guard. For more information, see [Oracle Data Guard Protection Modes](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-protection-modes.htm#SBYDB02000) in the Oracle Data Guard documentation.
     * 
     */
    public String protectionMode() {
        return this.protectionMode;
    }
    /**
     * @return Specifies a prefix for the `Oracle SID` of the database to be created.
     * 
     */
    public String sidPrefix() {
        return this.sidPrefix;
    }
    public String sourceDatabaseId() {
        return this.sourceDatabaseId;
    }
    public List<GetDatabasesDatabaseDatabaseSourceEncryptionKeyLocationDetail> sourceEncryptionKeyLocationDetails() {
        return this.sourceEncryptionKeyLocationDetails;
    }
    public String sourceTdeWalletPassword() {
        return this.sourceTdeWalletPassword;
    }
    public String tdeWalletPassword() {
        return this.tdeWalletPassword;
    }
    /**
     * @return The redo transport type to use for this Data Guard association.  Valid values depend on the specified `protectionMode`:
     * * MAXIMUM_AVAILABILITY - SYNC or FASTSYNC
     * * MAXIMUM_PERFORMANCE - ASYNC
     * * MAXIMUM_PROTECTION - SYNC
     * 
     */
    public String transportType() {
        return this.transportType;
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

    public static Builder builder(GetDatabasesDatabaseDatabase defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String adminPassword;
        private String backupId;
        private String backupTdePassword;
        private String characterSet;
        private String databaseAdminPassword;
        private String databaseSoftwareImageId;
        private List<GetDatabasesDatabaseDatabaseDbBackupConfig> dbBackupConfigs;
        private String dbName;
        private String dbUniqueName;
        private String dbWorkload;
        private Map<String,String> definedTags;
        private List<GetDatabasesDatabaseDatabaseEncryptionKeyLocationDetail> encryptionKeyLocationDetails;
        private Map<String,String> freeformTags;
        private Boolean isActiveDataGuardEnabled;
        private String kmsKeyId;
        private String kmsKeyVersionId;
        private String ncharacterSet;
        private String pdbName;
        private List<String> pluggableDatabases;
        private String protectionMode;
        private String sidPrefix;
        private String sourceDatabaseId;
        private List<GetDatabasesDatabaseDatabaseSourceEncryptionKeyLocationDetail> sourceEncryptionKeyLocationDetails;
        private String sourceTdeWalletPassword;
        private String tdeWalletPassword;
        private String transportType;
        private String vaultId;
        public Builder() {}
        public Builder(GetDatabasesDatabaseDatabase defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.adminPassword = defaults.adminPassword;
    	      this.backupId = defaults.backupId;
    	      this.backupTdePassword = defaults.backupTdePassword;
    	      this.characterSet = defaults.characterSet;
    	      this.databaseAdminPassword = defaults.databaseAdminPassword;
    	      this.databaseSoftwareImageId = defaults.databaseSoftwareImageId;
    	      this.dbBackupConfigs = defaults.dbBackupConfigs;
    	      this.dbName = defaults.dbName;
    	      this.dbUniqueName = defaults.dbUniqueName;
    	      this.dbWorkload = defaults.dbWorkload;
    	      this.definedTags = defaults.definedTags;
    	      this.encryptionKeyLocationDetails = defaults.encryptionKeyLocationDetails;
    	      this.freeformTags = defaults.freeformTags;
    	      this.isActiveDataGuardEnabled = defaults.isActiveDataGuardEnabled;
    	      this.kmsKeyId = defaults.kmsKeyId;
    	      this.kmsKeyVersionId = defaults.kmsKeyVersionId;
    	      this.ncharacterSet = defaults.ncharacterSet;
    	      this.pdbName = defaults.pdbName;
    	      this.pluggableDatabases = defaults.pluggableDatabases;
    	      this.protectionMode = defaults.protectionMode;
    	      this.sidPrefix = defaults.sidPrefix;
    	      this.sourceDatabaseId = defaults.sourceDatabaseId;
    	      this.sourceEncryptionKeyLocationDetails = defaults.sourceEncryptionKeyLocationDetails;
    	      this.sourceTdeWalletPassword = defaults.sourceTdeWalletPassword;
    	      this.tdeWalletPassword = defaults.tdeWalletPassword;
    	      this.transportType = defaults.transportType;
    	      this.vaultId = defaults.vaultId;
        }

        @CustomType.Setter
        public Builder adminPassword(String adminPassword) {
            if (adminPassword == null) {
              throw new MissingRequiredPropertyException("GetDatabasesDatabaseDatabase", "adminPassword");
            }
            this.adminPassword = adminPassword;
            return this;
        }
        @CustomType.Setter
        public Builder backupId(String backupId) {
            if (backupId == null) {
              throw new MissingRequiredPropertyException("GetDatabasesDatabaseDatabase", "backupId");
            }
            this.backupId = backupId;
            return this;
        }
        @CustomType.Setter
        public Builder backupTdePassword(String backupTdePassword) {
            if (backupTdePassword == null) {
              throw new MissingRequiredPropertyException("GetDatabasesDatabaseDatabase", "backupTdePassword");
            }
            this.backupTdePassword = backupTdePassword;
            return this;
        }
        @CustomType.Setter
        public Builder characterSet(String characterSet) {
            if (characterSet == null) {
              throw new MissingRequiredPropertyException("GetDatabasesDatabaseDatabase", "characterSet");
            }
            this.characterSet = characterSet;
            return this;
        }
        @CustomType.Setter
        public Builder databaseAdminPassword(String databaseAdminPassword) {
            if (databaseAdminPassword == null) {
              throw new MissingRequiredPropertyException("GetDatabasesDatabaseDatabase", "databaseAdminPassword");
            }
            this.databaseAdminPassword = databaseAdminPassword;
            return this;
        }
        @CustomType.Setter
        public Builder databaseSoftwareImageId(String databaseSoftwareImageId) {
            if (databaseSoftwareImageId == null) {
              throw new MissingRequiredPropertyException("GetDatabasesDatabaseDatabase", "databaseSoftwareImageId");
            }
            this.databaseSoftwareImageId = databaseSoftwareImageId;
            return this;
        }
        @CustomType.Setter
        public Builder dbBackupConfigs(List<GetDatabasesDatabaseDatabaseDbBackupConfig> dbBackupConfigs) {
            if (dbBackupConfigs == null) {
              throw new MissingRequiredPropertyException("GetDatabasesDatabaseDatabase", "dbBackupConfigs");
            }
            this.dbBackupConfigs = dbBackupConfigs;
            return this;
        }
        public Builder dbBackupConfigs(GetDatabasesDatabaseDatabaseDbBackupConfig... dbBackupConfigs) {
            return dbBackupConfigs(List.of(dbBackupConfigs));
        }
        @CustomType.Setter
        public Builder dbName(String dbName) {
            if (dbName == null) {
              throw new MissingRequiredPropertyException("GetDatabasesDatabaseDatabase", "dbName");
            }
            this.dbName = dbName;
            return this;
        }
        @CustomType.Setter
        public Builder dbUniqueName(String dbUniqueName) {
            if (dbUniqueName == null) {
              throw new MissingRequiredPropertyException("GetDatabasesDatabaseDatabase", "dbUniqueName");
            }
            this.dbUniqueName = dbUniqueName;
            return this;
        }
        @CustomType.Setter
        public Builder dbWorkload(String dbWorkload) {
            if (dbWorkload == null) {
              throw new MissingRequiredPropertyException("GetDatabasesDatabaseDatabase", "dbWorkload");
            }
            this.dbWorkload = dbWorkload;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetDatabasesDatabaseDatabase", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder encryptionKeyLocationDetails(List<GetDatabasesDatabaseDatabaseEncryptionKeyLocationDetail> encryptionKeyLocationDetails) {
            if (encryptionKeyLocationDetails == null) {
              throw new MissingRequiredPropertyException("GetDatabasesDatabaseDatabase", "encryptionKeyLocationDetails");
            }
            this.encryptionKeyLocationDetails = encryptionKeyLocationDetails;
            return this;
        }
        public Builder encryptionKeyLocationDetails(GetDatabasesDatabaseDatabaseEncryptionKeyLocationDetail... encryptionKeyLocationDetails) {
            return encryptionKeyLocationDetails(List.of(encryptionKeyLocationDetails));
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetDatabasesDatabaseDatabase", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder isActiveDataGuardEnabled(Boolean isActiveDataGuardEnabled) {
            if (isActiveDataGuardEnabled == null) {
              throw new MissingRequiredPropertyException("GetDatabasesDatabaseDatabase", "isActiveDataGuardEnabled");
            }
            this.isActiveDataGuardEnabled = isActiveDataGuardEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder kmsKeyId(String kmsKeyId) {
            if (kmsKeyId == null) {
              throw new MissingRequiredPropertyException("GetDatabasesDatabaseDatabase", "kmsKeyId");
            }
            this.kmsKeyId = kmsKeyId;
            return this;
        }
        @CustomType.Setter
        public Builder kmsKeyVersionId(String kmsKeyVersionId) {
            if (kmsKeyVersionId == null) {
              throw new MissingRequiredPropertyException("GetDatabasesDatabaseDatabase", "kmsKeyVersionId");
            }
            this.kmsKeyVersionId = kmsKeyVersionId;
            return this;
        }
        @CustomType.Setter
        public Builder ncharacterSet(String ncharacterSet) {
            if (ncharacterSet == null) {
              throw new MissingRequiredPropertyException("GetDatabasesDatabaseDatabase", "ncharacterSet");
            }
            this.ncharacterSet = ncharacterSet;
            return this;
        }
        @CustomType.Setter
        public Builder pdbName(String pdbName) {
            if (pdbName == null) {
              throw new MissingRequiredPropertyException("GetDatabasesDatabaseDatabase", "pdbName");
            }
            this.pdbName = pdbName;
            return this;
        }
        @CustomType.Setter
        public Builder pluggableDatabases(List<String> pluggableDatabases) {
            if (pluggableDatabases == null) {
              throw new MissingRequiredPropertyException("GetDatabasesDatabaseDatabase", "pluggableDatabases");
            }
            this.pluggableDatabases = pluggableDatabases;
            return this;
        }
        public Builder pluggableDatabases(String... pluggableDatabases) {
            return pluggableDatabases(List.of(pluggableDatabases));
        }
        @CustomType.Setter
        public Builder protectionMode(String protectionMode) {
            if (protectionMode == null) {
              throw new MissingRequiredPropertyException("GetDatabasesDatabaseDatabase", "protectionMode");
            }
            this.protectionMode = protectionMode;
            return this;
        }
        @CustomType.Setter
        public Builder sidPrefix(String sidPrefix) {
            if (sidPrefix == null) {
              throw new MissingRequiredPropertyException("GetDatabasesDatabaseDatabase", "sidPrefix");
            }
            this.sidPrefix = sidPrefix;
            return this;
        }
        @CustomType.Setter
        public Builder sourceDatabaseId(String sourceDatabaseId) {
            if (sourceDatabaseId == null) {
              throw new MissingRequiredPropertyException("GetDatabasesDatabaseDatabase", "sourceDatabaseId");
            }
            this.sourceDatabaseId = sourceDatabaseId;
            return this;
        }
        @CustomType.Setter
        public Builder sourceEncryptionKeyLocationDetails(List<GetDatabasesDatabaseDatabaseSourceEncryptionKeyLocationDetail> sourceEncryptionKeyLocationDetails) {
            if (sourceEncryptionKeyLocationDetails == null) {
              throw new MissingRequiredPropertyException("GetDatabasesDatabaseDatabase", "sourceEncryptionKeyLocationDetails");
            }
            this.sourceEncryptionKeyLocationDetails = sourceEncryptionKeyLocationDetails;
            return this;
        }
        public Builder sourceEncryptionKeyLocationDetails(GetDatabasesDatabaseDatabaseSourceEncryptionKeyLocationDetail... sourceEncryptionKeyLocationDetails) {
            return sourceEncryptionKeyLocationDetails(List.of(sourceEncryptionKeyLocationDetails));
        }
        @CustomType.Setter
        public Builder sourceTdeWalletPassword(String sourceTdeWalletPassword) {
            if (sourceTdeWalletPassword == null) {
              throw new MissingRequiredPropertyException("GetDatabasesDatabaseDatabase", "sourceTdeWalletPassword");
            }
            this.sourceTdeWalletPassword = sourceTdeWalletPassword;
            return this;
        }
        @CustomType.Setter
        public Builder tdeWalletPassword(String tdeWalletPassword) {
            if (tdeWalletPassword == null) {
              throw new MissingRequiredPropertyException("GetDatabasesDatabaseDatabase", "tdeWalletPassword");
            }
            this.tdeWalletPassword = tdeWalletPassword;
            return this;
        }
        @CustomType.Setter
        public Builder transportType(String transportType) {
            if (transportType == null) {
              throw new MissingRequiredPropertyException("GetDatabasesDatabaseDatabase", "transportType");
            }
            this.transportType = transportType;
            return this;
        }
        @CustomType.Setter
        public Builder vaultId(String vaultId) {
            if (vaultId == null) {
              throw new MissingRequiredPropertyException("GetDatabasesDatabaseDatabase", "vaultId");
            }
            this.vaultId = vaultId;
            return this;
        }
        public GetDatabasesDatabaseDatabase build() {
            final var _resultValue = new GetDatabasesDatabaseDatabase();
            _resultValue.adminPassword = adminPassword;
            _resultValue.backupId = backupId;
            _resultValue.backupTdePassword = backupTdePassword;
            _resultValue.characterSet = characterSet;
            _resultValue.databaseAdminPassword = databaseAdminPassword;
            _resultValue.databaseSoftwareImageId = databaseSoftwareImageId;
            _resultValue.dbBackupConfigs = dbBackupConfigs;
            _resultValue.dbName = dbName;
            _resultValue.dbUniqueName = dbUniqueName;
            _resultValue.dbWorkload = dbWorkload;
            _resultValue.definedTags = definedTags;
            _resultValue.encryptionKeyLocationDetails = encryptionKeyLocationDetails;
            _resultValue.freeformTags = freeformTags;
            _resultValue.isActiveDataGuardEnabled = isActiveDataGuardEnabled;
            _resultValue.kmsKeyId = kmsKeyId;
            _resultValue.kmsKeyVersionId = kmsKeyVersionId;
            _resultValue.ncharacterSet = ncharacterSet;
            _resultValue.pdbName = pdbName;
            _resultValue.pluggableDatabases = pluggableDatabases;
            _resultValue.protectionMode = protectionMode;
            _resultValue.sidPrefix = sidPrefix;
            _resultValue.sourceDatabaseId = sourceDatabaseId;
            _resultValue.sourceEncryptionKeyLocationDetails = sourceEncryptionKeyLocationDetails;
            _resultValue.sourceTdeWalletPassword = sourceTdeWalletPassword;
            _resultValue.tdeWalletPassword = tdeWalletPassword;
            _resultValue.transportType = transportType;
            _resultValue.vaultId = vaultId;
            return _resultValue;
        }
    }
}
