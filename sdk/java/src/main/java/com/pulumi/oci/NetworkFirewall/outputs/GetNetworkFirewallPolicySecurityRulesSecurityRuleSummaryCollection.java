// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.NetworkFirewall.outputs.GetNetworkFirewallPolicySecurityRulesSecurityRuleSummaryCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetNetworkFirewallPolicySecurityRulesSecurityRuleSummaryCollection {
    private List<GetNetworkFirewallPolicySecurityRulesSecurityRuleSummaryCollectionItem> items;

    private GetNetworkFirewallPolicySecurityRulesSecurityRuleSummaryCollection() {}
    public List<GetNetworkFirewallPolicySecurityRulesSecurityRuleSummaryCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNetworkFirewallPolicySecurityRulesSecurityRuleSummaryCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetNetworkFirewallPolicySecurityRulesSecurityRuleSummaryCollectionItem> items;
        public Builder() {}
        public Builder(GetNetworkFirewallPolicySecurityRulesSecurityRuleSummaryCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetNetworkFirewallPolicySecurityRulesSecurityRuleSummaryCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallPolicySecurityRulesSecurityRuleSummaryCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetNetworkFirewallPolicySecurityRulesSecurityRuleSummaryCollectionItem... items) {
            return items(List.of(items));
        }
        public GetNetworkFirewallPolicySecurityRulesSecurityRuleSummaryCollection build() {
            final var _resultValue = new GetNetworkFirewallPolicySecurityRulesSecurityRuleSummaryCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
