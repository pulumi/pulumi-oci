// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Identity.outputs.GetAuthenticationPolicyNetworkPolicy;
import com.pulumi.oci.Identity.outputs.GetAuthenticationPolicyPasswordPolicy;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetAuthenticationPolicyResult {
    /**
     * @return Compartment OCID.
     * 
     */
    private String compartmentId;
    private String id;
    /**
     * @return Network policy, Consists of a list of Network Source ids.
     * 
     */
    private List<GetAuthenticationPolicyNetworkPolicy> networkPolicies;
    /**
     * @return Password policy, currently set for the given compartment.
     * 
     */
    private List<GetAuthenticationPolicyPasswordPolicy> passwordPolicies;

    private GetAuthenticationPolicyResult() {}
    /**
     * @return Compartment OCID.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public String id() {
        return this.id;
    }
    /**
     * @return Network policy, Consists of a list of Network Source ids.
     * 
     */
    public List<GetAuthenticationPolicyNetworkPolicy> networkPolicies() {
        return this.networkPolicies;
    }
    /**
     * @return Password policy, currently set for the given compartment.
     * 
     */
    public List<GetAuthenticationPolicyPasswordPolicy> passwordPolicies() {
        return this.passwordPolicies;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAuthenticationPolicyResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private String id;
        private List<GetAuthenticationPolicyNetworkPolicy> networkPolicies;
        private List<GetAuthenticationPolicyPasswordPolicy> passwordPolicies;
        public Builder() {}
        public Builder(GetAuthenticationPolicyResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.id = defaults.id;
    	      this.networkPolicies = defaults.networkPolicies;
    	      this.passwordPolicies = defaults.passwordPolicies;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder networkPolicies(List<GetAuthenticationPolicyNetworkPolicy> networkPolicies) {
            this.networkPolicies = Objects.requireNonNull(networkPolicies);
            return this;
        }
        public Builder networkPolicies(GetAuthenticationPolicyNetworkPolicy... networkPolicies) {
            return networkPolicies(List.of(networkPolicies));
        }
        @CustomType.Setter
        public Builder passwordPolicies(List<GetAuthenticationPolicyPasswordPolicy> passwordPolicies) {
            this.passwordPolicies = Objects.requireNonNull(passwordPolicies);
            return this;
        }
        public Builder passwordPolicies(GetAuthenticationPolicyPasswordPolicy... passwordPolicies) {
            return passwordPolicies(List.of(passwordPolicies));
        }
        public GetAuthenticationPolicyResult build() {
            final var o = new GetAuthenticationPolicyResult();
            o.compartmentId = compartmentId;
            o.id = id;
            o.networkPolicies = networkPolicies;
            o.passwordPolicies = passwordPolicies;
            return o;
        }
    }
}