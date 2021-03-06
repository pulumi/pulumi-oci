// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.LoadBalancer.outputs.GetLoadBalancerRoutingPoliciesFilter;
import com.pulumi.oci.LoadBalancer.outputs.GetLoadBalancerRoutingPoliciesRoutingPolicy;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetLoadBalancerRoutingPoliciesResult {
    private final @Nullable List<GetLoadBalancerRoutingPoliciesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    private final String loadBalancerId;
    /**
     * @return The list of routing_policies.
     * 
     */
    private final List<GetLoadBalancerRoutingPoliciesRoutingPolicy> routingPolicies;

    @CustomType.Constructor
    private GetLoadBalancerRoutingPoliciesResult(
        @CustomType.Parameter("filters") @Nullable List<GetLoadBalancerRoutingPoliciesFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("loadBalancerId") String loadBalancerId,
        @CustomType.Parameter("routingPolicies") List<GetLoadBalancerRoutingPoliciesRoutingPolicy> routingPolicies) {
        this.filters = filters;
        this.id = id;
        this.loadBalancerId = loadBalancerId;
        this.routingPolicies = routingPolicies;
    }

    public List<GetLoadBalancerRoutingPoliciesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String loadBalancerId() {
        return this.loadBalancerId;
    }
    /**
     * @return The list of routing_policies.
     * 
     */
    public List<GetLoadBalancerRoutingPoliciesRoutingPolicy> routingPolicies() {
        return this.routingPolicies;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetLoadBalancerRoutingPoliciesResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable List<GetLoadBalancerRoutingPoliciesFilter> filters;
        private String id;
        private String loadBalancerId;
        private List<GetLoadBalancerRoutingPoliciesRoutingPolicy> routingPolicies;

        public Builder() {
    	      // Empty
        }

        public Builder(GetLoadBalancerRoutingPoliciesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.loadBalancerId = defaults.loadBalancerId;
    	      this.routingPolicies = defaults.routingPolicies;
        }

        public Builder filters(@Nullable List<GetLoadBalancerRoutingPoliciesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetLoadBalancerRoutingPoliciesFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder loadBalancerId(String loadBalancerId) {
            this.loadBalancerId = Objects.requireNonNull(loadBalancerId);
            return this;
        }
        public Builder routingPolicies(List<GetLoadBalancerRoutingPoliciesRoutingPolicy> routingPolicies) {
            this.routingPolicies = Objects.requireNonNull(routingPolicies);
            return this;
        }
        public Builder routingPolicies(GetLoadBalancerRoutingPoliciesRoutingPolicy... routingPolicies) {
            return routingPolicies(List.of(routingPolicies));
        }        public GetLoadBalancerRoutingPoliciesResult build() {
            return new GetLoadBalancerRoutingPoliciesResult(filters, id, loadBalancerId, routingPolicies);
        }
    }
}
