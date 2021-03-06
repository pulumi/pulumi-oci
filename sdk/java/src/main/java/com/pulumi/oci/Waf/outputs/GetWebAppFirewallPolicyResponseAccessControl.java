// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waf.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Waf.outputs.GetWebAppFirewallPolicyResponseAccessControlRule;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetWebAppFirewallPolicyResponseAccessControl {
    /**
     * @return Ordered list of ProtectionRules. Rules are executed in order of appearance in this array. ProtectionRules in this array can only use protection capabilities of RESPONSE_PROTECTION_CAPABILITY type.
     * 
     */
    private final List<GetWebAppFirewallPolicyResponseAccessControlRule> rules;

    @CustomType.Constructor
    private GetWebAppFirewallPolicyResponseAccessControl(@CustomType.Parameter("rules") List<GetWebAppFirewallPolicyResponseAccessControlRule> rules) {
        this.rules = rules;
    }

    /**
     * @return Ordered list of ProtectionRules. Rules are executed in order of appearance in this array. ProtectionRules in this array can only use protection capabilities of RESPONSE_PROTECTION_CAPABILITY type.
     * 
     */
    public List<GetWebAppFirewallPolicyResponseAccessControlRule> rules() {
        return this.rules;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWebAppFirewallPolicyResponseAccessControl defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetWebAppFirewallPolicyResponseAccessControlRule> rules;

        public Builder() {
    	      // Empty
        }

        public Builder(GetWebAppFirewallPolicyResponseAccessControl defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.rules = defaults.rules;
        }

        public Builder rules(List<GetWebAppFirewallPolicyResponseAccessControlRule> rules) {
            this.rules = Objects.requireNonNull(rules);
            return this;
        }
        public Builder rules(GetWebAppFirewallPolicyResponseAccessControlRule... rules) {
            return rules(List.of(rules));
        }        public GetWebAppFirewallPolicyResponseAccessControl build() {
            return new GetWebAppFirewallPolicyResponseAccessControl(rules);
        }
    }
}
