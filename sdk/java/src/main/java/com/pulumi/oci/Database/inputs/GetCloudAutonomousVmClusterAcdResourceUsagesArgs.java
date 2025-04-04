// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.inputs.GetCloudAutonomousVmClusterAcdResourceUsagesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetCloudAutonomousVmClusterAcdResourceUsagesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetCloudAutonomousVmClusterAcdResourceUsagesArgs Empty = new GetCloudAutonomousVmClusterAcdResourceUsagesArgs();

    /**
     * The Cloud VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="cloudAutonomousVmClusterId", required=true)
    private Output<String> cloudAutonomousVmClusterId;

    /**
     * @return The Cloud VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Output<String> cloudAutonomousVmClusterId() {
        return this.cloudAutonomousVmClusterId;
    }

    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetCloudAutonomousVmClusterAcdResourceUsagesFilterArgs>> filters;

    public Optional<Output<List<GetCloudAutonomousVmClusterAcdResourceUsagesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetCloudAutonomousVmClusterAcdResourceUsagesArgs() {}

    private GetCloudAutonomousVmClusterAcdResourceUsagesArgs(GetCloudAutonomousVmClusterAcdResourceUsagesArgs $) {
        this.cloudAutonomousVmClusterId = $.cloudAutonomousVmClusterId;
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetCloudAutonomousVmClusterAcdResourceUsagesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetCloudAutonomousVmClusterAcdResourceUsagesArgs $;

        public Builder() {
            $ = new GetCloudAutonomousVmClusterAcdResourceUsagesArgs();
        }

        public Builder(GetCloudAutonomousVmClusterAcdResourceUsagesArgs defaults) {
            $ = new GetCloudAutonomousVmClusterAcdResourceUsagesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param cloudAutonomousVmClusterId The Cloud VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder cloudAutonomousVmClusterId(Output<String> cloudAutonomousVmClusterId) {
            $.cloudAutonomousVmClusterId = cloudAutonomousVmClusterId;
            return this;
        }

        /**
         * @param cloudAutonomousVmClusterId The Cloud VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder cloudAutonomousVmClusterId(String cloudAutonomousVmClusterId) {
            return cloudAutonomousVmClusterId(Output.of(cloudAutonomousVmClusterId));
        }

        /**
         * @param compartmentId The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public Builder filters(@Nullable Output<List<GetCloudAutonomousVmClusterAcdResourceUsagesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetCloudAutonomousVmClusterAcdResourceUsagesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetCloudAutonomousVmClusterAcdResourceUsagesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        public GetCloudAutonomousVmClusterAcdResourceUsagesArgs build() {
            if ($.cloudAutonomousVmClusterId == null) {
                throw new MissingRequiredPropertyException("GetCloudAutonomousVmClusterAcdResourceUsagesArgs", "cloudAutonomousVmClusterId");
            }
            return $;
        }
    }

}
