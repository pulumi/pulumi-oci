// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDatabasesDatabaseDbBackupConfigBackupDestinationDetail {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DBRS policy used for backup.
     * 
     */
    private String dbrsPolicyId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database.
     * 
     */
    private String id;
    /**
     * @return Indicates whether the backup destination is cross-region or local region.
     * 
     */
    private Boolean isRemote;
    /**
     * @return The name of the remote region where the remote automatic incremental backups will be stored.
     * 
     */
    private String remoteRegion;
    /**
     * @return Type of the database backup destination.
     * 
     */
    private String type;
    private String vpcPassword;
    private String vpcUser;

    private GetDatabasesDatabaseDbBackupConfigBackupDestinationDetail() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DBRS policy used for backup.
     * 
     */
    public String dbrsPolicyId() {
        return this.dbrsPolicyId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Indicates whether the backup destination is cross-region or local region.
     * 
     */
    public Boolean isRemote() {
        return this.isRemote;
    }
    /**
     * @return The name of the remote region where the remote automatic incremental backups will be stored.
     * 
     */
    public String remoteRegion() {
        return this.remoteRegion;
    }
    /**
     * @return Type of the database backup destination.
     * 
     */
    public String type() {
        return this.type;
    }
    public String vpcPassword() {
        return this.vpcPassword;
    }
    public String vpcUser() {
        return this.vpcUser;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDatabasesDatabaseDbBackupConfigBackupDestinationDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String dbrsPolicyId;
        private String id;
        private Boolean isRemote;
        private String remoteRegion;
        private String type;
        private String vpcPassword;
        private String vpcUser;
        public Builder() {}
        public Builder(GetDatabasesDatabaseDbBackupConfigBackupDestinationDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.dbrsPolicyId = defaults.dbrsPolicyId;
    	      this.id = defaults.id;
    	      this.isRemote = defaults.isRemote;
    	      this.remoteRegion = defaults.remoteRegion;
    	      this.type = defaults.type;
    	      this.vpcPassword = defaults.vpcPassword;
    	      this.vpcUser = defaults.vpcUser;
        }

        @CustomType.Setter
        public Builder dbrsPolicyId(String dbrsPolicyId) {
            if (dbrsPolicyId == null) {
              throw new MissingRequiredPropertyException("GetDatabasesDatabaseDbBackupConfigBackupDestinationDetail", "dbrsPolicyId");
            }
            this.dbrsPolicyId = dbrsPolicyId;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetDatabasesDatabaseDbBackupConfigBackupDestinationDetail", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder isRemote(Boolean isRemote) {
            if (isRemote == null) {
              throw new MissingRequiredPropertyException("GetDatabasesDatabaseDbBackupConfigBackupDestinationDetail", "isRemote");
            }
            this.isRemote = isRemote;
            return this;
        }
        @CustomType.Setter
        public Builder remoteRegion(String remoteRegion) {
            if (remoteRegion == null) {
              throw new MissingRequiredPropertyException("GetDatabasesDatabaseDbBackupConfigBackupDestinationDetail", "remoteRegion");
            }
            this.remoteRegion = remoteRegion;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("GetDatabasesDatabaseDbBackupConfigBackupDestinationDetail", "type");
            }
            this.type = type;
            return this;
        }
        @CustomType.Setter
        public Builder vpcPassword(String vpcPassword) {
            if (vpcPassword == null) {
              throw new MissingRequiredPropertyException("GetDatabasesDatabaseDbBackupConfigBackupDestinationDetail", "vpcPassword");
            }
            this.vpcPassword = vpcPassword;
            return this;
        }
        @CustomType.Setter
        public Builder vpcUser(String vpcUser) {
            if (vpcUser == null) {
              throw new MissingRequiredPropertyException("GetDatabasesDatabaseDbBackupConfigBackupDestinationDetail", "vpcUser");
            }
            this.vpcUser = vpcUser;
            return this;
        }
        public GetDatabasesDatabaseDbBackupConfigBackupDestinationDetail build() {
            final var _resultValue = new GetDatabasesDatabaseDbBackupConfigBackupDestinationDetail();
            _resultValue.dbrsPolicyId = dbrsPolicyId;
            _resultValue.id = id;
            _resultValue.isRemote = isRemote;
            _resultValue.remoteRegion = remoteRegion;
            _resultValue.type = type;
            _resultValue.vpcPassword = vpcPassword;
            _resultValue.vpcUser = vpcUser;
            return _resultValue;
        }
    }
}
