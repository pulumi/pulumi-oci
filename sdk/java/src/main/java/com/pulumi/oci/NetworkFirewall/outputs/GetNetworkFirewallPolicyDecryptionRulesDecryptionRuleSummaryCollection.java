// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.NetworkFirewall.outputs.GetNetworkFirewallPolicyDecryptionRulesDecryptionRuleSummaryCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetNetworkFirewallPolicyDecryptionRulesDecryptionRuleSummaryCollection {
    private List<GetNetworkFirewallPolicyDecryptionRulesDecryptionRuleSummaryCollectionItem> items;

    private GetNetworkFirewallPolicyDecryptionRulesDecryptionRuleSummaryCollection() {}
    public List<GetNetworkFirewallPolicyDecryptionRulesDecryptionRuleSummaryCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNetworkFirewallPolicyDecryptionRulesDecryptionRuleSummaryCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetNetworkFirewallPolicyDecryptionRulesDecryptionRuleSummaryCollectionItem> items;
        public Builder() {}
        public Builder(GetNetworkFirewallPolicyDecryptionRulesDecryptionRuleSummaryCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetNetworkFirewallPolicyDecryptionRulesDecryptionRuleSummaryCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetNetworkFirewallPolicyDecryptionRulesDecryptionRuleSummaryCollectionItem... items) {
            return items(List.of(items));
        }
        public GetNetworkFirewallPolicyDecryptionRulesDecryptionRuleSummaryCollection build() {
            final var o = new GetNetworkFirewallPolicyDecryptionRulesDecryptionRuleSummaryCollection();
            o.items = items;
            return o;
        }
    }
}