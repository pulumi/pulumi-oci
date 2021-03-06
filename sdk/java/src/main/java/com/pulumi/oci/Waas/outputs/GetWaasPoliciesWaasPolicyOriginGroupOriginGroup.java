// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waas.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetWaasPoliciesWaasPolicyOriginGroupOriginGroup {
    /**
     * @return The key in the map of origins referencing the origin used for the Web Application Firewall. The origin must already be included in `Origins`. Required when creating the `WafConfig` resource, but not on update.
     * 
     */
    private final String origin;
    private final Integer weight;

    @CustomType.Constructor
    private GetWaasPoliciesWaasPolicyOriginGroupOriginGroup(
        @CustomType.Parameter("origin") String origin,
        @CustomType.Parameter("weight") Integer weight) {
        this.origin = origin;
        this.weight = weight;
    }

    /**
     * @return The key in the map of origins referencing the origin used for the Web Application Firewall. The origin must already be included in `Origins`. Required when creating the `WafConfig` resource, but not on update.
     * 
     */
    public String origin() {
        return this.origin;
    }
    public Integer weight() {
        return this.weight;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWaasPoliciesWaasPolicyOriginGroupOriginGroup defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String origin;
        private Integer weight;

        public Builder() {
    	      // Empty
        }

        public Builder(GetWaasPoliciesWaasPolicyOriginGroupOriginGroup defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.origin = defaults.origin;
    	      this.weight = defaults.weight;
        }

        public Builder origin(String origin) {
            this.origin = Objects.requireNonNull(origin);
            return this;
        }
        public Builder weight(Integer weight) {
            this.weight = Objects.requireNonNull(weight);
            return this;
        }        public GetWaasPoliciesWaasPolicyOriginGroupOriginGroup build() {
            return new GetWaasPoliciesWaasPolicyOriginGroupOriginGroup(origin, weight);
        }
    }
}
