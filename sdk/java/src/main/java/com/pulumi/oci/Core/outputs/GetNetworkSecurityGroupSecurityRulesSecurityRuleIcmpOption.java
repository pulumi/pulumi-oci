// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.util.Objects;

@CustomType
public final class GetNetworkSecurityGroupSecurityRulesSecurityRuleIcmpOption {
    /**
     * @return The ICMP code (optional).
     * 
     */
    private final Integer code;
    /**
     * @return The ICMP type.
     * 
     */
    private final Integer type;

    @CustomType.Constructor
    private GetNetworkSecurityGroupSecurityRulesSecurityRuleIcmpOption(
        @CustomType.Parameter("code") Integer code,
        @CustomType.Parameter("type") Integer type) {
        this.code = code;
        this.type = type;
    }

    /**
     * @return The ICMP code (optional).
     * 
     */
    public Integer code() {
        return this.code;
    }
    /**
     * @return The ICMP type.
     * 
     */
    public Integer type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNetworkSecurityGroupSecurityRulesSecurityRuleIcmpOption defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private Integer code;
        private Integer type;

        public Builder() {
    	      // Empty
        }

        public Builder(GetNetworkSecurityGroupSecurityRulesSecurityRuleIcmpOption defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.code = defaults.code;
    	      this.type = defaults.type;
        }

        public Builder code(Integer code) {
            this.code = Objects.requireNonNull(code);
            return this;
        }
        public Builder type(Integer type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }        public GetNetworkSecurityGroupSecurityRulesSecurityRuleIcmpOption build() {
            return new GetNetworkSecurityGroupSecurityRulesSecurityRuleIcmpOption(code, type);
        }
    }
}
