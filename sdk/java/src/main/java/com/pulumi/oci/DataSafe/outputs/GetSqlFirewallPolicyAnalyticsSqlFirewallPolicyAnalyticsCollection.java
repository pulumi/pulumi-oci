// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataSafe.outputs.GetSqlFirewallPolicyAnalyticsSqlFirewallPolicyAnalyticsCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetSqlFirewallPolicyAnalyticsSqlFirewallPolicyAnalyticsCollection {
    /**
     * @return The aggregated data point items.
     * 
     */
    private List<GetSqlFirewallPolicyAnalyticsSqlFirewallPolicyAnalyticsCollectionItem> items;

    private GetSqlFirewallPolicyAnalyticsSqlFirewallPolicyAnalyticsCollection() {}
    /**
     * @return The aggregated data point items.
     * 
     */
    public List<GetSqlFirewallPolicyAnalyticsSqlFirewallPolicyAnalyticsCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSqlFirewallPolicyAnalyticsSqlFirewallPolicyAnalyticsCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetSqlFirewallPolicyAnalyticsSqlFirewallPolicyAnalyticsCollectionItem> items;
        public Builder() {}
        public Builder(GetSqlFirewallPolicyAnalyticsSqlFirewallPolicyAnalyticsCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetSqlFirewallPolicyAnalyticsSqlFirewallPolicyAnalyticsCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetSqlFirewallPolicyAnalyticsSqlFirewallPolicyAnalyticsCollectionItem... items) {
            return items(List.of(items));
        }
        public GetSqlFirewallPolicyAnalyticsSqlFirewallPolicyAnalyticsCollection build() {
            final var o = new GetSqlFirewallPolicyAnalyticsSqlFirewallPolicyAnalyticsCollection();
            o.items = items;
            return o;
        }
    }
}