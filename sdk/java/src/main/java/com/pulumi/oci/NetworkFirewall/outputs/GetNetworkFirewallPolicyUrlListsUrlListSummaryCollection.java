// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.NetworkFirewall.outputs.GetNetworkFirewallPolicyUrlListsUrlListSummaryCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetNetworkFirewallPolicyUrlListsUrlListSummaryCollection {
    private List<GetNetworkFirewallPolicyUrlListsUrlListSummaryCollectionItem> items;

    private GetNetworkFirewallPolicyUrlListsUrlListSummaryCollection() {}
    public List<GetNetworkFirewallPolicyUrlListsUrlListSummaryCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNetworkFirewallPolicyUrlListsUrlListSummaryCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetNetworkFirewallPolicyUrlListsUrlListSummaryCollectionItem> items;
        public Builder() {}
        public Builder(GetNetworkFirewallPolicyUrlListsUrlListSummaryCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetNetworkFirewallPolicyUrlListsUrlListSummaryCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallPolicyUrlListsUrlListSummaryCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetNetworkFirewallPolicyUrlListsUrlListSummaryCollectionItem... items) {
            return items(List.of(items));
        }
        public GetNetworkFirewallPolicyUrlListsUrlListSummaryCollection build() {
            final var _resultValue = new GetNetworkFirewallPolicyUrlListsUrlListSummaryCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
