// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetLoadBalancerRoutingPoliciesRoutingPolicyRuleAction {
    /**
     * @return Name of the backend set the listener will forward the traffic to.  Example: `backendSetForImages`
     * 
     */
    private String backendSetName;
    /**
     * @return A unique name for the routing policy rule. Avoid entering confidential information.
     * 
     */
    private String name;

    private GetLoadBalancerRoutingPoliciesRoutingPolicyRuleAction() {}
    /**
     * @return Name of the backend set the listener will forward the traffic to.  Example: `backendSetForImages`
     * 
     */
    public String backendSetName() {
        return this.backendSetName;
    }
    /**
     * @return A unique name for the routing policy rule. Avoid entering confidential information.
     * 
     */
    public String name() {
        return this.name;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetLoadBalancerRoutingPoliciesRoutingPolicyRuleAction defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String backendSetName;
        private String name;
        public Builder() {}
        public Builder(GetLoadBalancerRoutingPoliciesRoutingPolicyRuleAction defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.backendSetName = defaults.backendSetName;
    	      this.name = defaults.name;
        }

        @CustomType.Setter
        public Builder backendSetName(String backendSetName) {
            this.backendSetName = Objects.requireNonNull(backendSetName);
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public GetLoadBalancerRoutingPoliciesRoutingPolicyRuleAction build() {
            final var o = new GetLoadBalancerRoutingPoliciesRoutingPolicyRuleAction();
            o.backendSetName = backendSetName;
            o.name = name;
            return o;
        }
    }
}