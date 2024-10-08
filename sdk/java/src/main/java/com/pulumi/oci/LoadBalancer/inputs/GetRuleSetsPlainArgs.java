// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.LoadBalancer.inputs.GetRuleSetsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetRuleSetsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetRuleSetsPlainArgs Empty = new GetRuleSetsPlainArgs();

    @Import(name="filters")
    private @Nullable List<GetRuleSetsFilter> filters;

    public Optional<List<GetRuleSetsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the specified load balancer.
     * 
     */
    @Import(name="loadBalancerId", required=true)
    private String loadBalancerId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the specified load balancer.
     * 
     */
    public String loadBalancerId() {
        return this.loadBalancerId;
    }

    private GetRuleSetsPlainArgs() {}

    private GetRuleSetsPlainArgs(GetRuleSetsPlainArgs $) {
        this.filters = $.filters;
        this.loadBalancerId = $.loadBalancerId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetRuleSetsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetRuleSetsPlainArgs $;

        public Builder() {
            $ = new GetRuleSetsPlainArgs();
        }

        public Builder(GetRuleSetsPlainArgs defaults) {
            $ = new GetRuleSetsPlainArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable List<GetRuleSetsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetRuleSetsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param loadBalancerId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the specified load balancer.
         * 
         * @return builder
         * 
         */
        public Builder loadBalancerId(String loadBalancerId) {
            $.loadBalancerId = loadBalancerId;
            return this;
        }

        public GetRuleSetsPlainArgs build() {
            if ($.loadBalancerId == null) {
                throw new MissingRequiredPropertyException("GetRuleSetsPlainArgs", "loadBalancerId");
            }
            return $;
        }
    }

}
