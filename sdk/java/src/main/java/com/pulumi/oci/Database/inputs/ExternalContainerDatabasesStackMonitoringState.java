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


public final class ExternalContainerDatabasesStackMonitoringState extends com.pulumi.resources.ResourceArgs {

    public static final ExternalContainerDatabasesStackMonitoringState Empty = new ExternalContainerDatabasesStackMonitoringState();

    /**
     * (Updatable) Enabling Stack Monitoring on External Container Databases . Requires boolean value &#34;true&#34; or &#34;false&#34;.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="enableStackMonitoring")
    private @Nullable Output<Boolean> enableStackMonitoring;

    /**
     * @return (Updatable) Enabling Stack Monitoring on External Container Databases . Requires boolean value &#34;true&#34; or &#34;false&#34;.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<Boolean>> enableStackMonitoring() {
        return Optional.ofNullable(this.enableStackMonitoring);
    }

    /**
     * The ExternalContainerDatabase [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="externalContainerDatabaseId")
    private @Nullable Output<String> externalContainerDatabaseId;

    /**
     * @return The ExternalContainerDatabase [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Optional<Output<String>> externalContainerDatabaseId() {
        return Optional.ofNullable(this.externalContainerDatabaseId);
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

    private ExternalContainerDatabasesStackMonitoringState() {}

    private ExternalContainerDatabasesStackMonitoringState(ExternalContainerDatabasesStackMonitoringState $) {
        this.enableStackMonitoring = $.enableStackMonitoring;
        this.externalContainerDatabaseId = $.externalContainerDatabaseId;
        this.externalDatabaseConnectorId = $.externalDatabaseConnectorId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ExternalContainerDatabasesStackMonitoringState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ExternalContainerDatabasesStackMonitoringState $;

        public Builder() {
            $ = new ExternalContainerDatabasesStackMonitoringState();
        }

        public Builder(ExternalContainerDatabasesStackMonitoringState defaults) {
            $ = new ExternalContainerDatabasesStackMonitoringState(Objects.requireNonNull(defaults));
        }

        /**
         * @param enableStackMonitoring (Updatable) Enabling Stack Monitoring on External Container Databases . Requires boolean value &#34;true&#34; or &#34;false&#34;.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder enableStackMonitoring(@Nullable Output<Boolean> enableStackMonitoring) {
            $.enableStackMonitoring = enableStackMonitoring;
            return this;
        }

        /**
         * @param enableStackMonitoring (Updatable) Enabling Stack Monitoring on External Container Databases . Requires boolean value &#34;true&#34; or &#34;false&#34;.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder enableStackMonitoring(Boolean enableStackMonitoring) {
            return enableStackMonitoring(Output.of(enableStackMonitoring));
        }

        /**
         * @param externalContainerDatabaseId The ExternalContainerDatabase [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder externalContainerDatabaseId(@Nullable Output<String> externalContainerDatabaseId) {
            $.externalContainerDatabaseId = externalContainerDatabaseId;
            return this;
        }

        /**
         * @param externalContainerDatabaseId The ExternalContainerDatabase [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder externalContainerDatabaseId(String externalContainerDatabaseId) {
            return externalContainerDatabaseId(Output.of(externalContainerDatabaseId));
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

        public ExternalContainerDatabasesStackMonitoringState build() {
            return $;
        }
    }

}
