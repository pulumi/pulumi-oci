// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.NetworkFirewall.outputs.GetNetworkFirewallPolicyServiceListsServiceListSummaryCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetNetworkFirewallPolicyServiceListsServiceListSummaryCollection {
    private List<GetNetworkFirewallPolicyServiceListsServiceListSummaryCollectionItem> items;

    private GetNetworkFirewallPolicyServiceListsServiceListSummaryCollection() {}
    public List<GetNetworkFirewallPolicyServiceListsServiceListSummaryCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNetworkFirewallPolicyServiceListsServiceListSummaryCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetNetworkFirewallPolicyServiceListsServiceListSummaryCollectionItem> items;
        public Builder() {}
        public Builder(GetNetworkFirewallPolicyServiceListsServiceListSummaryCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetNetworkFirewallPolicyServiceListsServiceListSummaryCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetNetworkFirewallPolicyServiceListsServiceListSummaryCollectionItem... items) {
            return items(List.of(items));
        }
        public GetNetworkFirewallPolicyServiceListsServiceListSummaryCollection build() {
            final var o = new GetNetworkFirewallPolicyServiceListsServiceListSummaryCollection();
            o.items = items;
            return o;
        }
    }
}