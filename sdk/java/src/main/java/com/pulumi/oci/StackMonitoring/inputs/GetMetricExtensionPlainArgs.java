// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetMetricExtensionPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetMetricExtensionPlainArgs Empty = new GetMetricExtensionPlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the metric extension resource.
     * 
     */
    @Import(name="metricExtensionId", required=true)
    private String metricExtensionId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the metric extension resource.
     * 
     */
    public String metricExtensionId() {
        return this.metricExtensionId;
    }

    private GetMetricExtensionPlainArgs() {}

    private GetMetricExtensionPlainArgs(GetMetricExtensionPlainArgs $) {
        this.metricExtensionId = $.metricExtensionId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetMetricExtensionPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetMetricExtensionPlainArgs $;

        public Builder() {
            $ = new GetMetricExtensionPlainArgs();
        }

        public Builder(GetMetricExtensionPlainArgs defaults) {
            $ = new GetMetricExtensionPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param metricExtensionId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the metric extension resource.
         * 
         * @return builder
         * 
         */
        public Builder metricExtensionId(String metricExtensionId) {
            $.metricExtensionId = metricExtensionId;
            return this;
        }

        public GetMetricExtensionPlainArgs build() {
            $.metricExtensionId = Objects.requireNonNull($.metricExtensionId, "expected parameter 'metricExtensionId' to be non-null");
            return $;
        }
    }

}