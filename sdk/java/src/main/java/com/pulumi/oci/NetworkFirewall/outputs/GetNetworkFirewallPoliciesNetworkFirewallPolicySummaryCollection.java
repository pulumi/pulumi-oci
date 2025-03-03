// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.NetworkFirewall.outputs.GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollection {
    private List<GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollectionItem> items;

    private GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollection() {}
    public List<GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollectionItem> items;
        public Builder() {}
        public Builder(GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollectionItem... items) {
            return items(List.of(items));
        }
        public GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollection build() {
            final var _resultValue = new GetNetworkFirewallPoliciesNetworkFirewallPolicySummaryCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
