// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Sch.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Sch.inputs.ConnectorSourceMonitoringSourceNamespaceDetailsArgs;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ConnectorSourceMonitoringSourceArgs extends com.pulumi.resources.ResourceArgs {

    public static final ConnectorSourceMonitoringSourceArgs Empty = new ConnectorSourceMonitoringSourceArgs();

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the metric.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the metric.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * (Updatable) Discriminator for namespaces in the compartment-specific list.
     * 
     */
    @Import(name="namespaceDetails")
    private @Nullable Output<ConnectorSourceMonitoringSourceNamespaceDetailsArgs> namespaceDetails;

    /**
     * @return (Updatable) Discriminator for namespaces in the compartment-specific list.
     * 
     */
    public Optional<Output<ConnectorSourceMonitoringSourceNamespaceDetailsArgs>> namespaceDetails() {
        return Optional.ofNullable(this.namespaceDetails);
    }

    private ConnectorSourceMonitoringSourceArgs() {}

    private ConnectorSourceMonitoringSourceArgs(ConnectorSourceMonitoringSourceArgs $) {
        this.compartmentId = $.compartmentId;
        this.namespaceDetails = $.namespaceDetails;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ConnectorSourceMonitoringSourceArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ConnectorSourceMonitoringSourceArgs $;

        public Builder() {
            $ = new ConnectorSourceMonitoringSourceArgs();
        }

        public Builder(ConnectorSourceMonitoringSourceArgs defaults) {
            $ = new ConnectorSourceMonitoringSourceArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the metric.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the metric.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param namespaceDetails (Updatable) Discriminator for namespaces in the compartment-specific list.
         * 
         * @return builder
         * 
         */
        public Builder namespaceDetails(@Nullable Output<ConnectorSourceMonitoringSourceNamespaceDetailsArgs> namespaceDetails) {
            $.namespaceDetails = namespaceDetails;
            return this;
        }

        /**
         * @param namespaceDetails (Updatable) Discriminator for namespaces in the compartment-specific list.
         * 
         * @return builder
         * 
         */
        public Builder namespaceDetails(ConnectorSourceMonitoringSourceNamespaceDetailsArgs namespaceDetails) {
            return namespaceDetails(Output.of(namespaceDetails));
        }

        public ConnectorSourceMonitoringSourceArgs build() {
            return $;
        }
    }

}