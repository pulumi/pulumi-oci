// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class MonitoredResourcesAssociateMonitoredResourceArgs extends com.pulumi.resources.ResourceArgs {

    public static final MonitoredResourcesAssociateMonitoredResourceArgs Empty = new MonitoredResourcesAssociateMonitoredResourceArgs();

    /**
     * Association type to be created between source and destination resources.
     * 
     */
    @Import(name="associationType", required=true)
    private Output<String> associationType;

    /**
     * @return Association type to be created between source and destination resources.
     * 
     */
    public Output<String> associationType() {
        return this.associationType;
    }

    /**
     * Compartment Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return Compartment Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * Destination Monitored Resource Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="destinationResourceId", required=true)
    private Output<String> destinationResourceId;

    /**
     * @return Destination Monitored Resource Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Output<String> destinationResourceId() {
        return this.destinationResourceId;
    }

    /**
     * Source Monitored Resource Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="sourceResourceId", required=true)
    private Output<String> sourceResourceId;

    /**
     * @return Source Monitored Resource Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> sourceResourceId() {
        return this.sourceResourceId;
    }

    private MonitoredResourcesAssociateMonitoredResourceArgs() {}

    private MonitoredResourcesAssociateMonitoredResourceArgs(MonitoredResourcesAssociateMonitoredResourceArgs $) {
        this.associationType = $.associationType;
        this.compartmentId = $.compartmentId;
        this.destinationResourceId = $.destinationResourceId;
        this.sourceResourceId = $.sourceResourceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MonitoredResourcesAssociateMonitoredResourceArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MonitoredResourcesAssociateMonitoredResourceArgs $;

        public Builder() {
            $ = new MonitoredResourcesAssociateMonitoredResourceArgs();
        }

        public Builder(MonitoredResourcesAssociateMonitoredResourceArgs defaults) {
            $ = new MonitoredResourcesAssociateMonitoredResourceArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param associationType Association type to be created between source and destination resources.
         * 
         * @return builder
         * 
         */
        public Builder associationType(Output<String> associationType) {
            $.associationType = associationType;
            return this;
        }

        /**
         * @param associationType Association type to be created between source and destination resources.
         * 
         * @return builder
         * 
         */
        public Builder associationType(String associationType) {
            return associationType(Output.of(associationType));
        }

        /**
         * @param compartmentId Compartment Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId Compartment Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param destinationResourceId Destination Monitored Resource Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder destinationResourceId(Output<String> destinationResourceId) {
            $.destinationResourceId = destinationResourceId;
            return this;
        }

        /**
         * @param destinationResourceId Destination Monitored Resource Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder destinationResourceId(String destinationResourceId) {
            return destinationResourceId(Output.of(destinationResourceId));
        }

        /**
         * @param sourceResourceId Source Monitored Resource Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder sourceResourceId(Output<String> sourceResourceId) {
            $.sourceResourceId = sourceResourceId;
            return this;
        }

        /**
         * @param sourceResourceId Source Monitored Resource Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder sourceResourceId(String sourceResourceId) {
            return sourceResourceId(Output.of(sourceResourceId));
        }

        public MonitoredResourcesAssociateMonitoredResourceArgs build() {
            if ($.associationType == null) {
                throw new MissingRequiredPropertyException("MonitoredResourcesAssociateMonitoredResourceArgs", "associationType");
            }
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("MonitoredResourcesAssociateMonitoredResourceArgs", "compartmentId");
            }
            if ($.destinationResourceId == null) {
                throw new MissingRequiredPropertyException("MonitoredResourcesAssociateMonitoredResourceArgs", "destinationResourceId");
            }
            if ($.sourceResourceId == null) {
                throw new MissingRequiredPropertyException("MonitoredResourcesAssociateMonitoredResourceArgs", "sourceResourceId");
            }
            return $;
        }
    }

}
