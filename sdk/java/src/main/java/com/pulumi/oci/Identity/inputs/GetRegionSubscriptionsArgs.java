// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Identity.inputs.GetRegionSubscriptionsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetRegionSubscriptionsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetRegionSubscriptionsArgs Empty = new GetRegionSubscriptionsArgs();

    @Import(name="filters")
    private @Nullable Output<List<GetRegionSubscriptionsFilterArgs>> filters;

    public Optional<Output<List<GetRegionSubscriptionsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The OCID of the tenancy.
     * 
     */
    @Import(name="tenancyId", required=true)
    private Output<String> tenancyId;

    /**
     * @return The OCID of the tenancy.
     * 
     */
    public Output<String> tenancyId() {
        return this.tenancyId;
    }

    private GetRegionSubscriptionsArgs() {}

    private GetRegionSubscriptionsArgs(GetRegionSubscriptionsArgs $) {
        this.filters = $.filters;
        this.tenancyId = $.tenancyId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetRegionSubscriptionsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetRegionSubscriptionsArgs $;

        public Builder() {
            $ = new GetRegionSubscriptionsArgs();
        }

        public Builder(GetRegionSubscriptionsArgs defaults) {
            $ = new GetRegionSubscriptionsArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable Output<List<GetRegionSubscriptionsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetRegionSubscriptionsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetRegionSubscriptionsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param tenancyId The OCID of the tenancy.
         * 
         * @return builder
         * 
         */
        public Builder tenancyId(Output<String> tenancyId) {
            $.tenancyId = tenancyId;
            return this;
        }

        /**
         * @param tenancyId The OCID of the tenancy.
         * 
         * @return builder
         * 
         */
        public Builder tenancyId(String tenancyId) {
            return tenancyId(Output.of(tenancyId));
        }

        public GetRegionSubscriptionsArgs build() {
            $.tenancyId = Objects.requireNonNull($.tenancyId, "expected parameter 'tenancyId' to be non-null");
            return $;
        }
    }

}