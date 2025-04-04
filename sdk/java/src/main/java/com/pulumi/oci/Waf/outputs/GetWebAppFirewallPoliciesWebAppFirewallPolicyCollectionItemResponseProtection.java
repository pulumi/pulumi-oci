// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waf.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Waf.outputs.GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemResponseProtectionRule;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemResponseProtection {
    /**
     * @return Ordered list of ProtectionRules. Rules are executed in order of appearance in this array. ProtectionRules in this array can only use protection capabilities of RESPONSE_PROTECTION_CAPABILITY type.
     * 
     */
    private List<GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemResponseProtectionRule> rules;

    private GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemResponseProtection() {}
    /**
     * @return Ordered list of ProtectionRules. Rules are executed in order of appearance in this array. ProtectionRules in this array can only use protection capabilities of RESPONSE_PROTECTION_CAPABILITY type.
     * 
     */
    public List<GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemResponseProtectionRule> rules() {
        return this.rules;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemResponseProtection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemResponseProtectionRule> rules;
        public Builder() {}
        public Builder(GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemResponseProtection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.rules = defaults.rules;
        }

        @CustomType.Setter
        public Builder rules(List<GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemResponseProtectionRule> rules) {
            if (rules == null) {
              throw new MissingRequiredPropertyException("GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemResponseProtection", "rules");
            }
            this.rules = rules;
            return this;
        }
        public Builder rules(GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemResponseProtectionRule... rules) {
            return rules(List.of(rules));
        }
        public GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemResponseProtection build() {
            final var _resultValue = new GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemResponseProtection();
            _resultValue.rules = rules;
            return _resultValue;
        }
    }
}
