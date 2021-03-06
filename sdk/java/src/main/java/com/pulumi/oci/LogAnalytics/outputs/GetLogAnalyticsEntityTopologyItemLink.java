// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.LogAnalytics.outputs.GetLogAnalyticsEntityTopologyItemLinkItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetLogAnalyticsEntityTopologyItemLink {
    /**
     * @return Array of log analytics entity summary.
     * 
     */
    private final List<GetLogAnalyticsEntityTopologyItemLinkItem> items;

    @CustomType.Constructor
    private GetLogAnalyticsEntityTopologyItemLink(@CustomType.Parameter("items") List<GetLogAnalyticsEntityTopologyItemLinkItem> items) {
        this.items = items;
    }

    /**
     * @return Array of log analytics entity summary.
     * 
     */
    public List<GetLogAnalyticsEntityTopologyItemLinkItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetLogAnalyticsEntityTopologyItemLink defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetLogAnalyticsEntityTopologyItemLinkItem> items;

        public Builder() {
    	      // Empty
        }

        public Builder(GetLogAnalyticsEntityTopologyItemLink defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        public Builder items(List<GetLogAnalyticsEntityTopologyItemLinkItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetLogAnalyticsEntityTopologyItemLinkItem... items) {
            return items(List.of(items));
        }        public GetLogAnalyticsEntityTopologyItemLink build() {
            return new GetLogAnalyticsEntityTopologyItemLink(items);
        }
    }
}
