// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetNetworkFirewallPolicyUrlListUrlListValue {
    private String pattern;
    /**
     * @return Type of the secrets mapped based on the policy.
     * 
     */
    private String type;

    private GetNetworkFirewallPolicyUrlListUrlListValue() {}
    public String pattern() {
        return this.pattern;
    }
    /**
     * @return Type of the secrets mapped based on the policy.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNetworkFirewallPolicyUrlListUrlListValue defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String pattern;
        private String type;
        public Builder() {}
        public Builder(GetNetworkFirewallPolicyUrlListUrlListValue defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.pattern = defaults.pattern;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder pattern(String pattern) {
            this.pattern = Objects.requireNonNull(pattern);
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        public GetNetworkFirewallPolicyUrlListUrlListValue build() {
            final var o = new GetNetworkFirewallPolicyUrlListUrlListValue();
            o.pattern = pattern;
            o.type = type;
            return o;
        }
    }
}