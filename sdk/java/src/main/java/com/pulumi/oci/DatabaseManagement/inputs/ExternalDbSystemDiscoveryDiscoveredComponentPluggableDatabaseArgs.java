// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DatabaseManagement.inputs.ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseConnectorArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseArgs extends com.pulumi.resources.ResourceArgs {

    public static final ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseArgs Empty = new ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external DB system resides.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external DB system resides.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * The connector details used to connect to the external DB system component.
     * 
     */
    @Import(name="connectors")
    private @Nullable Output<List<ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseConnectorArgs>> connectors;

    /**
     * @return The connector details used to connect to the external DB system component.
     * 
     */
    public Optional<Output<List<ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseConnectorArgs>>> connectors() {
        return Optional.ofNullable(this.connectors);
    }

    /**
     * The unique identifier of the parent Container Database (CDB).
     * 
     */
    @Import(name="containerDatabaseId")
    private @Nullable Output<String> containerDatabaseId;

    /**
     * @return The unique identifier of the parent Container Database (CDB).
     * 
     */
    public Optional<Output<String>> containerDatabaseId() {
        return Optional.ofNullable(this.containerDatabaseId);
    }

    /**
     * The unique identifier of the PDB.
     * 
     */
    @Import(name="guid")
    private @Nullable Output<String> guid;

    /**
     * @return The unique identifier of the PDB.
     * 
     */
    public Optional<Output<String>> guid() {
        return Optional.ofNullable(this.guid);
    }

    private ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseArgs() {}

    private ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseArgs(ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseArgs $) {
        this.compartmentId = $.compartmentId;
        this.connectors = $.connectors;
        this.containerDatabaseId = $.containerDatabaseId;
        this.guid = $.guid;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseArgs $;

        public Builder() {
            $ = new ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseArgs();
        }

        public Builder(ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseArgs defaults) {
            $ = new ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external DB system resides.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external DB system resides.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param connectors The connector details used to connect to the external DB system component.
         * 
         * @return builder
         * 
         */
        public Builder connectors(@Nullable Output<List<ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseConnectorArgs>> connectors) {
            $.connectors = connectors;
            return this;
        }

        /**
         * @param connectors The connector details used to connect to the external DB system component.
         * 
         * @return builder
         * 
         */
        public Builder connectors(List<ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseConnectorArgs> connectors) {
            return connectors(Output.of(connectors));
        }

        /**
         * @param connectors The connector details used to connect to the external DB system component.
         * 
         * @return builder
         * 
         */
        public Builder connectors(ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseConnectorArgs... connectors) {
            return connectors(List.of(connectors));
        }

        /**
         * @param containerDatabaseId The unique identifier of the parent Container Database (CDB).
         * 
         * @return builder
         * 
         */
        public Builder containerDatabaseId(@Nullable Output<String> containerDatabaseId) {
            $.containerDatabaseId = containerDatabaseId;
            return this;
        }

        /**
         * @param containerDatabaseId The unique identifier of the parent Container Database (CDB).
         * 
         * @return builder
         * 
         */
        public Builder containerDatabaseId(String containerDatabaseId) {
            return containerDatabaseId(Output.of(containerDatabaseId));
        }

        /**
         * @param guid The unique identifier of the PDB.
         * 
         * @return builder
         * 
         */
        public Builder guid(@Nullable Output<String> guid) {
            $.guid = guid;
            return this;
        }

        /**
         * @param guid The unique identifier of the PDB.
         * 
         * @return builder
         * 
         */
        public Builder guid(String guid) {
            return guid(Output.of(guid));
        }

        public ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseArgs build() {
            return $;
        }
    }

}