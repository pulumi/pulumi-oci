// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OneSubsription.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.OneSubsription.inputs.GetOrganizationSubscriptionsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetOrganizationSubscriptionsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetOrganizationSubscriptionsArgs Empty = new GetOrganizationSubscriptionsArgs();

    /**
     * The OCID of the root compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The OCID of the root compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable Output<List<GetOrganizationSubscriptionsFilterArgs>> filters;

    public Optional<Output<List<GetOrganizationSubscriptionsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetOrganizationSubscriptionsArgs() {}

    private GetOrganizationSubscriptionsArgs(GetOrganizationSubscriptionsArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetOrganizationSubscriptionsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetOrganizationSubscriptionsArgs $;

        public Builder() {
            $ = new GetOrganizationSubscriptionsArgs();
        }

        public Builder(GetOrganizationSubscriptionsArgs defaults) {
            $ = new GetOrganizationSubscriptionsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the root compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the root compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public Builder filters(@Nullable Output<List<GetOrganizationSubscriptionsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetOrganizationSubscriptionsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetOrganizationSubscriptionsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        public GetOrganizationSubscriptionsArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetOrganizationSubscriptionsArgs", "compartmentId");
            }
            return $;
        }
    }

}
