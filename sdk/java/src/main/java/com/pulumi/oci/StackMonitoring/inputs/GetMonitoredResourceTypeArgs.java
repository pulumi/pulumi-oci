// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetMonitoredResourceTypeArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetMonitoredResourceTypeArgs Empty = new GetMonitoredResourceTypeArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of monitored resource type.
     * 
     */
    @Import(name="monitoredResourceTypeId", required=true)
    private Output<String> monitoredResourceTypeId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of monitored resource type.
     * 
     */
    public Output<String> monitoredResourceTypeId() {
        return this.monitoredResourceTypeId;
    }

    private GetMonitoredResourceTypeArgs() {}

    private GetMonitoredResourceTypeArgs(GetMonitoredResourceTypeArgs $) {
        this.monitoredResourceTypeId = $.monitoredResourceTypeId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetMonitoredResourceTypeArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetMonitoredResourceTypeArgs $;

        public Builder() {
            $ = new GetMonitoredResourceTypeArgs();
        }

        public Builder(GetMonitoredResourceTypeArgs defaults) {
            $ = new GetMonitoredResourceTypeArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param monitoredResourceTypeId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of monitored resource type.
         * 
         * @return builder
         * 
         */
        public Builder monitoredResourceTypeId(Output<String> monitoredResourceTypeId) {
            $.monitoredResourceTypeId = monitoredResourceTypeId;
            return this;
        }

        /**
         * @param monitoredResourceTypeId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of monitored resource type.
         * 
         * @return builder
         * 
         */
        public Builder monitoredResourceTypeId(String monitoredResourceTypeId) {
            return monitoredResourceTypeId(Output.of(monitoredResourceTypeId));
        }

        public GetMonitoredResourceTypeArgs build() {
            if ($.monitoredResourceTypeId == null) {
                throw new MissingRequiredPropertyException("GetMonitoredResourceTypeArgs", "monitoredResourceTypeId");
            }
            return $;
        }
    }

}
