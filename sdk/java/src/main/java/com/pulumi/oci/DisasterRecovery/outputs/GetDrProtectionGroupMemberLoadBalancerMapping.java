// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DisasterRecovery.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDrProtectionGroupMemberLoadBalancerMapping {
    /**
     * @return The OCID of the destination Load Balancer.  Example: `ocid1.loadbalancer.oc1..uniqueID`
     * 
     */
    private String destinationLoadBalancerId;
    /**
     * @return The OCID of the source Load Balancer.  Example: `ocid1.loadbalancer.oc1..uniqueID`
     * 
     */
    private String sourceLoadBalancerId;

    private GetDrProtectionGroupMemberLoadBalancerMapping() {}
    /**
     * @return The OCID of the destination Load Balancer.  Example: `ocid1.loadbalancer.oc1..uniqueID`
     * 
     */
    public String destinationLoadBalancerId() {
        return this.destinationLoadBalancerId;
    }
    /**
     * @return The OCID of the source Load Balancer.  Example: `ocid1.loadbalancer.oc1..uniqueID`
     * 
     */
    public String sourceLoadBalancerId() {
        return this.sourceLoadBalancerId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDrProtectionGroupMemberLoadBalancerMapping defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String destinationLoadBalancerId;
        private String sourceLoadBalancerId;
        public Builder() {}
        public Builder(GetDrProtectionGroupMemberLoadBalancerMapping defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.destinationLoadBalancerId = defaults.destinationLoadBalancerId;
    	      this.sourceLoadBalancerId = defaults.sourceLoadBalancerId;
        }

        @CustomType.Setter
        public Builder destinationLoadBalancerId(String destinationLoadBalancerId) {
            if (destinationLoadBalancerId == null) {
              throw new MissingRequiredPropertyException("GetDrProtectionGroupMemberLoadBalancerMapping", "destinationLoadBalancerId");
            }
            this.destinationLoadBalancerId = destinationLoadBalancerId;
            return this;
        }
        @CustomType.Setter
        public Builder sourceLoadBalancerId(String sourceLoadBalancerId) {
            if (sourceLoadBalancerId == null) {
              throw new MissingRequiredPropertyException("GetDrProtectionGroupMemberLoadBalancerMapping", "sourceLoadBalancerId");
            }
            this.sourceLoadBalancerId = sourceLoadBalancerId;
            return this;
        }
        public GetDrProtectionGroupMemberLoadBalancerMapping build() {
            final var _resultValue = new GetDrProtectionGroupMemberLoadBalancerMapping();
            _resultValue.destinationLoadBalancerId = destinationLoadBalancerId;
            _resultValue.sourceLoadBalancerId = sourceLoadBalancerId;
            return _resultValue;
        }
    }
}
