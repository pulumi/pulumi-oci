// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ExternalPluggableDatabaseManagementState extends com.pulumi.resources.ResourceArgs {

    public static final ExternalPluggableDatabaseManagementState Empty = new ExternalPluggableDatabaseManagementState();

    @Import(name="enableManagement")
    private @Nullable Output<Boolean> enableManagement;

    public Optional<Output<Boolean>> enableManagement() {
        return Optional.ofNullable(this.enableManagement);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
     * 
     */
    @Import(name="externalDatabaseConnectorId")
    private @Nullable Output<String> externalDatabaseConnectorId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
     * 
     */
    public Optional<Output<String>> externalDatabaseConnectorId() {
        return Optional.ofNullable(this.externalDatabaseConnectorId);
    }

    /**
     * The ExternalPluggableDatabaseId [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="externalPluggableDatabaseId")
    private @Nullable Output<String> externalPluggableDatabaseId;

    /**
     * @return The ExternalPluggableDatabaseId [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> externalPluggableDatabaseId() {
        return Optional.ofNullable(this.externalPluggableDatabaseId);
    }

    private ExternalPluggableDatabaseManagementState() {}

    private ExternalPluggableDatabaseManagementState(ExternalPluggableDatabaseManagementState $) {
        this.enableManagement = $.enableManagement;
        this.externalDatabaseConnectorId = $.externalDatabaseConnectorId;
        this.externalPluggableDatabaseId = $.externalPluggableDatabaseId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ExternalPluggableDatabaseManagementState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ExternalPluggableDatabaseManagementState $;

        public Builder() {
            $ = new ExternalPluggableDatabaseManagementState();
        }

        public Builder(ExternalPluggableDatabaseManagementState defaults) {
            $ = new ExternalPluggableDatabaseManagementState(Objects.requireNonNull(defaults));
        }

        public Builder enableManagement(@Nullable Output<Boolean> enableManagement) {
            $.enableManagement = enableManagement;
            return this;
        }

        public Builder enableManagement(Boolean enableManagement) {
            return enableManagement(Output.of(enableManagement));
        }

        /**
         * @param externalDatabaseConnectorId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
         * 
         * @return builder
         * 
         */
        public Builder externalDatabaseConnectorId(@Nullable Output<String> externalDatabaseConnectorId) {
            $.externalDatabaseConnectorId = externalDatabaseConnectorId;
            return this;
        }

        /**
         * @param externalDatabaseConnectorId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
         * 
         * @return builder
         * 
         */
        public Builder externalDatabaseConnectorId(String externalDatabaseConnectorId) {
            return externalDatabaseConnectorId(Output.of(externalDatabaseConnectorId));
        }

        /**
         * @param externalPluggableDatabaseId The ExternalPluggableDatabaseId [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder externalPluggableDatabaseId(@Nullable Output<String> externalPluggableDatabaseId) {
            $.externalPluggableDatabaseId = externalPluggableDatabaseId;
            return this;
        }

        /**
         * @param externalPluggableDatabaseId The ExternalPluggableDatabaseId [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder externalPluggableDatabaseId(String externalPluggableDatabaseId) {
            return externalPluggableDatabaseId(Output.of(externalPluggableDatabaseId));
        }

        public ExternalPluggableDatabaseManagementState build() {
            return $;
        }
    }

}
