// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.UsageProxy.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.UsageProxy.outputs.GetSubscriptionRewardItem;
import com.pulumi.oci.UsageProxy.outputs.GetSubscriptionRewardSummary;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetSubscriptionRewardResult {
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The monthly summary of rewards.
     * 
     */
    private List<GetSubscriptionRewardItem> items;
    /**
     * @return The entitlement ID from MQS, which is the same as the subcription ID.
     * 
     */
    private String subscriptionId;
    /**
     * @return The overall monthly reward summary.
     * 
     */
    private List<GetSubscriptionRewardSummary> summaries;
    /**
     * @return The OCID of the target tenancy.
     * 
     */
    private String tenancyId;

    private GetSubscriptionRewardResult() {}
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The monthly summary of rewards.
     * 
     */
    public List<GetSubscriptionRewardItem> items() {
        return this.items;
    }
    /**
     * @return The entitlement ID from MQS, which is the same as the subcription ID.
     * 
     */
    public String subscriptionId() {
        return this.subscriptionId;
    }
    /**
     * @return The overall monthly reward summary.
     * 
     */
    public List<GetSubscriptionRewardSummary> summaries() {
        return this.summaries;
    }
    /**
     * @return The OCID of the target tenancy.
     * 
     */
    public String tenancyId() {
        return this.tenancyId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSubscriptionRewardResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String id;
        private List<GetSubscriptionRewardItem> items;
        private String subscriptionId;
        private List<GetSubscriptionRewardSummary> summaries;
        private String tenancyId;
        public Builder() {}
        public Builder(GetSubscriptionRewardResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.id = defaults.id;
    	      this.items = defaults.items;
    	      this.subscriptionId = defaults.subscriptionId;
    	      this.summaries = defaults.summaries;
    	      this.tenancyId = defaults.tenancyId;
        }

        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder items(List<GetSubscriptionRewardItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetSubscriptionRewardItem... items) {
            return items(List.of(items));
        }
        @CustomType.Setter
        public Builder subscriptionId(String subscriptionId) {
            this.subscriptionId = Objects.requireNonNull(subscriptionId);
            return this;
        }
        @CustomType.Setter
        public Builder summaries(List<GetSubscriptionRewardSummary> summaries) {
            this.summaries = Objects.requireNonNull(summaries);
            return this;
        }
        public Builder summaries(GetSubscriptionRewardSummary... summaries) {
            return summaries(List.of(summaries));
        }
        @CustomType.Setter
        public Builder tenancyId(String tenancyId) {
            this.tenancyId = Objects.requireNonNull(tenancyId);
            return this;
        }
        public GetSubscriptionRewardResult build() {
            final var o = new GetSubscriptionRewardResult();
            o.id = id;
            o.items = items;
            o.subscriptionId = subscriptionId;
            o.summaries = summaries;
            o.tenancyId = tenancyId;
            return o;
        }
    }
}