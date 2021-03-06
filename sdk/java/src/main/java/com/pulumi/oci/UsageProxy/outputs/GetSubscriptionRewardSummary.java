// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.UsageProxy.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Double;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetSubscriptionRewardSummary {
    /**
     * @return The currency unit for the reward amount.
     * 
     */
    private final String currency;
    /**
     * @return The redemption code used in the billing center during the reward redemption process
     * 
     */
    private final String redemptionCode;
    /**
     * @return The current Rewards percentage in decimal format.
     * 
     */
    private final Double rewardsRate;
    /**
     * @return The subscription ID for which rewards information is requested for.
     * 
     */
    private final String subscriptionId;
    /**
     * @return The OCID of the tenancy.
     * 
     */
    private final String tenancyId;
    /**
     * @return The total number of available rewards for a given subscription ID.
     * 
     */
    private final Double totalRewardsAvailable;

    @CustomType.Constructor
    private GetSubscriptionRewardSummary(
        @CustomType.Parameter("currency") String currency,
        @CustomType.Parameter("redemptionCode") String redemptionCode,
        @CustomType.Parameter("rewardsRate") Double rewardsRate,
        @CustomType.Parameter("subscriptionId") String subscriptionId,
        @CustomType.Parameter("tenancyId") String tenancyId,
        @CustomType.Parameter("totalRewardsAvailable") Double totalRewardsAvailable) {
        this.currency = currency;
        this.redemptionCode = redemptionCode;
        this.rewardsRate = rewardsRate;
        this.subscriptionId = subscriptionId;
        this.tenancyId = tenancyId;
        this.totalRewardsAvailable = totalRewardsAvailable;
    }

    /**
     * @return The currency unit for the reward amount.
     * 
     */
    public String currency() {
        return this.currency;
    }
    /**
     * @return The redemption code used in the billing center during the reward redemption process
     * 
     */
    public String redemptionCode() {
        return this.redemptionCode;
    }
    /**
     * @return The current Rewards percentage in decimal format.
     * 
     */
    public Double rewardsRate() {
        return this.rewardsRate;
    }
    /**
     * @return The subscription ID for which rewards information is requested for.
     * 
     */
    public String subscriptionId() {
        return this.subscriptionId;
    }
    /**
     * @return The OCID of the tenancy.
     * 
     */
    public String tenancyId() {
        return this.tenancyId;
    }
    /**
     * @return The total number of available rewards for a given subscription ID.
     * 
     */
    public Double totalRewardsAvailable() {
        return this.totalRewardsAvailable;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSubscriptionRewardSummary defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String currency;
        private String redemptionCode;
        private Double rewardsRate;
        private String subscriptionId;
        private String tenancyId;
        private Double totalRewardsAvailable;

        public Builder() {
    	      // Empty
        }

        public Builder(GetSubscriptionRewardSummary defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.currency = defaults.currency;
    	      this.redemptionCode = defaults.redemptionCode;
    	      this.rewardsRate = defaults.rewardsRate;
    	      this.subscriptionId = defaults.subscriptionId;
    	      this.tenancyId = defaults.tenancyId;
    	      this.totalRewardsAvailable = defaults.totalRewardsAvailable;
        }

        public Builder currency(String currency) {
            this.currency = Objects.requireNonNull(currency);
            return this;
        }
        public Builder redemptionCode(String redemptionCode) {
            this.redemptionCode = Objects.requireNonNull(redemptionCode);
            return this;
        }
        public Builder rewardsRate(Double rewardsRate) {
            this.rewardsRate = Objects.requireNonNull(rewardsRate);
            return this;
        }
        public Builder subscriptionId(String subscriptionId) {
            this.subscriptionId = Objects.requireNonNull(subscriptionId);
            return this;
        }
        public Builder tenancyId(String tenancyId) {
            this.tenancyId = Objects.requireNonNull(tenancyId);
            return this;
        }
        public Builder totalRewardsAvailable(Double totalRewardsAvailable) {
            this.totalRewardsAvailable = Objects.requireNonNull(totalRewardsAvailable);
            return this;
        }        public GetSubscriptionRewardSummary build() {
            return new GetSubscriptionRewardSummary(currency, redemptionCode, rewardsRate, subscriptionId, tenancyId, totalRewardsAvailable);
        }
    }
}
