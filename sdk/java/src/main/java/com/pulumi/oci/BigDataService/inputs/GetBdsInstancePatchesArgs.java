// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.BigDataService.inputs.GetBdsInstancePatchesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetBdsInstancePatchesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetBdsInstancePatchesArgs Empty = new GetBdsInstancePatchesArgs();

    /**
     * The OCID of the cluster.
     * 
     */
    @Import(name="bdsInstanceId", required=true)
    private Output<String> bdsInstanceId;

    /**
     * @return The OCID of the cluster.
     * 
     */
    public Output<String> bdsInstanceId() {
        return this.bdsInstanceId;
    }

    @Import(name="filters")
    private @Nullable Output<List<GetBdsInstancePatchesFilterArgs>> filters;

    public Optional<Output<List<GetBdsInstancePatchesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetBdsInstancePatchesArgs() {}

    private GetBdsInstancePatchesArgs(GetBdsInstancePatchesArgs $) {
        this.bdsInstanceId = $.bdsInstanceId;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetBdsInstancePatchesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetBdsInstancePatchesArgs $;

        public Builder() {
            $ = new GetBdsInstancePatchesArgs();
        }

        public Builder(GetBdsInstancePatchesArgs defaults) {
            $ = new GetBdsInstancePatchesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param bdsInstanceId The OCID of the cluster.
         * 
         * @return builder
         * 
         */
        public Builder bdsInstanceId(Output<String> bdsInstanceId) {
            $.bdsInstanceId = bdsInstanceId;
            return this;
        }

        /**
         * @param bdsInstanceId The OCID of the cluster.
         * 
         * @return builder
         * 
         */
        public Builder bdsInstanceId(String bdsInstanceId) {
            return bdsInstanceId(Output.of(bdsInstanceId));
        }

        public Builder filters(@Nullable Output<List<GetBdsInstancePatchesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetBdsInstancePatchesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetBdsInstancePatchesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        public GetBdsInstancePatchesArgs build() {
            $.bdsInstanceId = Objects.requireNonNull($.bdsInstanceId, "expected parameter 'bdsInstanceId' to be non-null");
            return $;
        }
    }

}