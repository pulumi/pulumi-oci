// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class AutonomousContainerDatabaseBackupConfigBackupDestinationDetails {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup destination.
     * 
     */
    private final @Nullable String id;
    /**
     * @return Proxy URL to connect to object store.
     * 
     */
    private final @Nullable String internetProxy;
    /**
     * @return Type of the database backup destination.
     * 
     */
    private final String type;
    /**
     * @return For a RECOVERY_APPLIANCE backup destination, the password for the VPC user that is used to access the Recovery Appliance.
     * 
     */
    private final @Nullable String vpcPassword;
    /**
     * @return For a RECOVERY_APPLIANCE backup destination, the Virtual Private Catalog (VPC) user that is used to access the Recovery Appliance.
     * 
     */
    private final @Nullable String vpcUser;

    @CustomType.Constructor
    private AutonomousContainerDatabaseBackupConfigBackupDestinationDetails(
        @CustomType.Parameter("id") @Nullable String id,
        @CustomType.Parameter("internetProxy") @Nullable String internetProxy,
        @CustomType.Parameter("type") String type,
        @CustomType.Parameter("vpcPassword") @Nullable String vpcPassword,
        @CustomType.Parameter("vpcUser") @Nullable String vpcUser) {
        this.id = id;
        this.internetProxy = internetProxy;
        this.type = type;
        this.vpcPassword = vpcPassword;
        this.vpcUser = vpcUser;
    }

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup destination.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return Proxy URL to connect to object store.
     * 
     */
    public Optional<String> internetProxy() {
        return Optional.ofNullable(this.internetProxy);
    }
    /**
     * @return Type of the database backup destination.
     * 
     */
    public String type() {
        return this.type;
    }
    /**
     * @return For a RECOVERY_APPLIANCE backup destination, the password for the VPC user that is used to access the Recovery Appliance.
     * 
     */
    public Optional<String> vpcPassword() {
        return Optional.ofNullable(this.vpcPassword);
    }
    /**
     * @return For a RECOVERY_APPLIANCE backup destination, the Virtual Private Catalog (VPC) user that is used to access the Recovery Appliance.
     * 
     */
    public Optional<String> vpcUser() {
        return Optional.ofNullable(this.vpcUser);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(AutonomousContainerDatabaseBackupConfigBackupDestinationDetails defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable String id;
        private @Nullable String internetProxy;
        private String type;
        private @Nullable String vpcPassword;
        private @Nullable String vpcUser;

        public Builder() {
    	      // Empty
        }

        public Builder(AutonomousContainerDatabaseBackupConfigBackupDestinationDetails defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.id = defaults.id;
    	      this.internetProxy = defaults.internetProxy;
    	      this.type = defaults.type;
    	      this.vpcPassword = defaults.vpcPassword;
    	      this.vpcUser = defaults.vpcUser;
        }

        public Builder id(@Nullable String id) {
            this.id = id;
            return this;
        }
        public Builder internetProxy(@Nullable String internetProxy) {
            this.internetProxy = internetProxy;
            return this;
        }
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        public Builder vpcPassword(@Nullable String vpcPassword) {
            this.vpcPassword = vpcPassword;
            return this;
        }
        public Builder vpcUser(@Nullable String vpcUser) {
            this.vpcUser = vpcUser;
            return this;
        }        public AutonomousContainerDatabaseBackupConfigBackupDestinationDetails build() {
            return new AutonomousContainerDatabaseBackupConfigBackupDestinationDetails(id, internetProxy, type, vpcPassword, vpcUser);
        }
    }
}
