// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DatabaseManagement.inputs.ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseConnectorConnectionInfoConnectionCredentialArgs;
import com.pulumi.oci.DatabaseManagement.inputs.ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseConnectorConnectionInfoConnectionStringArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseConnectorConnectionInfoArgs extends com.pulumi.resources.ResourceArgs {

    public static final ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseConnectorConnectionInfoArgs Empty = new ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseConnectorConnectionInfoArgs();

    /**
     * The component type.
     * 
     */
    @Import(name="componentType")
    private @Nullable Output<String> componentType;

    /**
     * @return The component type.
     * 
     */
    public Optional<Output<String>> componentType() {
        return Optional.ofNullable(this.componentType);
    }

    /**
     * The credentials used to connect to the ASM instance. Currently only the `DETAILS` type is supported for creating MACS connector credentials.
     * 
     */
    @Import(name="connectionCredentials")
    private @Nullable Output<List<ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseConnectorConnectionInfoConnectionCredentialArgs>> connectionCredentials;

    /**
     * @return The credentials used to connect to the ASM instance. Currently only the `DETAILS` type is supported for creating MACS connector credentials.
     * 
     */
    public Optional<Output<List<ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseConnectorConnectionInfoConnectionCredentialArgs>>> connectionCredentials() {
        return Optional.ofNullable(this.connectionCredentials);
    }

    /**
     * The Oracle Database connection string.
     * 
     */
    @Import(name="connectionStrings")
    private @Nullable Output<List<ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseConnectorConnectionInfoConnectionStringArgs>> connectionStrings;

    /**
     * @return The Oracle Database connection string.
     * 
     */
    public Optional<Output<List<ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseConnectorConnectionInfoConnectionStringArgs>>> connectionStrings() {
        return Optional.ofNullable(this.connectionStrings);
    }

    private ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseConnectorConnectionInfoArgs() {}

    private ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseConnectorConnectionInfoArgs(ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseConnectorConnectionInfoArgs $) {
        this.componentType = $.componentType;
        this.connectionCredentials = $.connectionCredentials;
        this.connectionStrings = $.connectionStrings;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseConnectorConnectionInfoArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseConnectorConnectionInfoArgs $;

        public Builder() {
            $ = new ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseConnectorConnectionInfoArgs();
        }

        public Builder(ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseConnectorConnectionInfoArgs defaults) {
            $ = new ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseConnectorConnectionInfoArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param componentType The component type.
         * 
         * @return builder
         * 
         */
        public Builder componentType(@Nullable Output<String> componentType) {
            $.componentType = componentType;
            return this;
        }

        /**
         * @param componentType The component type.
         * 
         * @return builder
         * 
         */
        public Builder componentType(String componentType) {
            return componentType(Output.of(componentType));
        }

        /**
         * @param connectionCredentials The credentials used to connect to the ASM instance. Currently only the `DETAILS` type is supported for creating MACS connector credentials.
         * 
         * @return builder
         * 
         */
        public Builder connectionCredentials(@Nullable Output<List<ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseConnectorConnectionInfoConnectionCredentialArgs>> connectionCredentials) {
            $.connectionCredentials = connectionCredentials;
            return this;
        }

        /**
         * @param connectionCredentials The credentials used to connect to the ASM instance. Currently only the `DETAILS` type is supported for creating MACS connector credentials.
         * 
         * @return builder
         * 
         */
        public Builder connectionCredentials(List<ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseConnectorConnectionInfoConnectionCredentialArgs> connectionCredentials) {
            return connectionCredentials(Output.of(connectionCredentials));
        }

        /**
         * @param connectionCredentials The credentials used to connect to the ASM instance. Currently only the `DETAILS` type is supported for creating MACS connector credentials.
         * 
         * @return builder
         * 
         */
        public Builder connectionCredentials(ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseConnectorConnectionInfoConnectionCredentialArgs... connectionCredentials) {
            return connectionCredentials(List.of(connectionCredentials));
        }

        /**
         * @param connectionStrings The Oracle Database connection string.
         * 
         * @return builder
         * 
         */
        public Builder connectionStrings(@Nullable Output<List<ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseConnectorConnectionInfoConnectionStringArgs>> connectionStrings) {
            $.connectionStrings = connectionStrings;
            return this;
        }

        /**
         * @param connectionStrings The Oracle Database connection string.
         * 
         * @return builder
         * 
         */
        public Builder connectionStrings(List<ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseConnectorConnectionInfoConnectionStringArgs> connectionStrings) {
            return connectionStrings(Output.of(connectionStrings));
        }

        /**
         * @param connectionStrings The Oracle Database connection string.
         * 
         * @return builder
         * 
         */
        public Builder connectionStrings(ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseConnectorConnectionInfoConnectionStringArgs... connectionStrings) {
            return connectionStrings(List.of(connectionStrings));
        }

        public ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseConnectorConnectionInfoArgs build() {
            return $;
        }
    }

}