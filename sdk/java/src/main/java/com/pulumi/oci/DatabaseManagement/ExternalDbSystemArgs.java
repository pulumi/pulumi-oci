// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DatabaseManagement.inputs.ExternalDbSystemDatabaseManagementConfigArgs;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ExternalDbSystemArgs extends com.pulumi.resources.ResourceArgs {

    public static final ExternalDbSystemArgs Empty = new ExternalDbSystemArgs();

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external DB system resides.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external DB system resides.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * The details required to enable Database Management for an external DB system.
     * 
     */
    @Import(name="databaseManagementConfig")
    private @Nullable Output<ExternalDbSystemDatabaseManagementConfigArgs> databaseManagementConfig;

    /**
     * @return The details required to enable Database Management for an external DB system.
     * 
     */
    public Optional<Output<ExternalDbSystemDatabaseManagementConfigArgs>> databaseManagementConfig() {
        return Optional.ofNullable(this.databaseManagementConfig);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system discovery.
     * 
     */
    @Import(name="dbSystemDiscoveryId", required=true)
    private Output<String> dbSystemDiscoveryId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system discovery.
     * 
     */
    public Output<String> dbSystemDiscoveryId() {
        return this.dbSystemDiscoveryId;
    }

    /**
     * (Updatable) The user-friendly name for the DB system. The name does not have to be unique.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) The user-friendly name for the DB system. The name does not have to be unique.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    private ExternalDbSystemArgs() {}

    private ExternalDbSystemArgs(ExternalDbSystemArgs $) {
        this.compartmentId = $.compartmentId;
        this.databaseManagementConfig = $.databaseManagementConfig;
        this.dbSystemDiscoveryId = $.dbSystemDiscoveryId;
        this.displayName = $.displayName;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ExternalDbSystemArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ExternalDbSystemArgs $;

        public Builder() {
            $ = new ExternalDbSystemArgs();
        }

        public Builder(ExternalDbSystemArgs defaults) {
            $ = new ExternalDbSystemArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external DB system resides.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external DB system resides.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param databaseManagementConfig The details required to enable Database Management for an external DB system.
         * 
         * @return builder
         * 
         */
        public Builder databaseManagementConfig(@Nullable Output<ExternalDbSystemDatabaseManagementConfigArgs> databaseManagementConfig) {
            $.databaseManagementConfig = databaseManagementConfig;
            return this;
        }

        /**
         * @param databaseManagementConfig The details required to enable Database Management for an external DB system.
         * 
         * @return builder
         * 
         */
        public Builder databaseManagementConfig(ExternalDbSystemDatabaseManagementConfigArgs databaseManagementConfig) {
            return databaseManagementConfig(Output.of(databaseManagementConfig));
        }

        /**
         * @param dbSystemDiscoveryId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system discovery.
         * 
         * @return builder
         * 
         */
        public Builder dbSystemDiscoveryId(Output<String> dbSystemDiscoveryId) {
            $.dbSystemDiscoveryId = dbSystemDiscoveryId;
            return this;
        }

        /**
         * @param dbSystemDiscoveryId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system discovery.
         * 
         * @return builder
         * 
         */
        public Builder dbSystemDiscoveryId(String dbSystemDiscoveryId) {
            return dbSystemDiscoveryId(Output.of(dbSystemDiscoveryId));
        }

        /**
         * @param displayName (Updatable) The user-friendly name for the DB system. The name does not have to be unique.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) The user-friendly name for the DB system. The name does not have to be unique.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public ExternalDbSystemArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.dbSystemDiscoveryId = Objects.requireNonNull($.dbSystemDiscoveryId, "expected parameter 'dbSystemDiscoveryId' to be non-null");
            return $;
        }
    }

}