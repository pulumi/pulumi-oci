// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.UsageProxy.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.UsageProxy.outputs.GetSubscriptionRewardsRewardCollectionItemItem;
import com.pulumi.oci.UsageProxy.outputs.GetSubscriptionRewardsRewardCollectionItemSummary;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetSubscriptionRewardsRewardCollectionItem {
    /**
     * @return The monthly summary of rewards.
     * 
     */
    private List<GetSubscriptionRewardsRewardCollectionItemItem> items;
    /**
     * @return The overall monthly reward summary.
     * 
     */
    private List<GetSubscriptionRewardsRewardCollectionItemSummary> summaries;

    private GetSubscriptionRewardsRewardCollectionItem() {}
    /**
     * @return The monthly summary of rewards.
     * 
     */
    public List<GetSubscriptionRewardsRewardCollectionItemItem> items() {
        return this.items;
    }
    /**
     * @return The overall monthly reward summary.
     * 
     */
    public List<GetSubscriptionRewardsRewardCollectionItemSummary> summaries() {
        return this.summaries;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSubscriptionRewardsRewardCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetSubscriptionRewardsRewardCollectionItemItem> items;
        private List<GetSubscriptionRewardsRewardCollectionItemSummary> summaries;
        public Builder() {}
        public Builder(GetSubscriptionRewardsRewardCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
    	      this.summaries = defaults.summaries;
        }

        @CustomType.Setter
        public Builder items(List<GetSubscriptionRewardsRewardCollectionItemItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetSubscriptionRewardsRewardCollectionItemItem... items) {
            return items(List.of(items));
        }
        @CustomType.Setter
        public Builder summaries(List<GetSubscriptionRewardsRewardCollectionItemSummary> summaries) {
            this.summaries = Objects.requireNonNull(summaries);
            return this;
        }
        public Builder summaries(GetSubscriptionRewardsRewardCollectionItemSummary... summaries) {
            return summaries(List.of(summaries));
        }
        public GetSubscriptionRewardsRewardCollectionItem build() {
            final var o = new GetSubscriptionRewardsRewardCollectionItem();
            o.items = items;
            o.summaries = summaries;
            return o;
        }
    }
}