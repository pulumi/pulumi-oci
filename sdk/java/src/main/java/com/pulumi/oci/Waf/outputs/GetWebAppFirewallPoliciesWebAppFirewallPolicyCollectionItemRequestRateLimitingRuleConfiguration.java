// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waf.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.util.Objects;

@CustomType
public final class GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestRateLimitingRuleConfiguration {
    /**
     * @return Duration of block action application in seconds when `requestsLimit` is reached. Optional and can be 0 (no block duration).
     * 
     */
    private Integer actionDurationInSeconds;
    /**
     * @return Evaluation period in seconds.
     * 
     */
    private Integer periodInSeconds;
    /**
     * @return Requests allowed per evaluation period.
     * 
     */
    private Integer requestsLimit;

    private GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestRateLimitingRuleConfiguration() {}
    /**
     * @return Duration of block action application in seconds when `requestsLimit` is reached. Optional and can be 0 (no block duration).
     * 
     */
    public Integer actionDurationInSeconds() {
        return this.actionDurationInSeconds;
    }
    /**
     * @return Evaluation period in seconds.
     * 
     */
    public Integer periodInSeconds() {
        return this.periodInSeconds;
    }
    /**
     * @return Requests allowed per evaluation period.
     * 
     */
    public Integer requestsLimit() {
        return this.requestsLimit;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestRateLimitingRuleConfiguration defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer actionDurationInSeconds;
        private Integer periodInSeconds;
        private Integer requestsLimit;
        public Builder() {}
        public Builder(GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestRateLimitingRuleConfiguration defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.actionDurationInSeconds = defaults.actionDurationInSeconds;
    	      this.periodInSeconds = defaults.periodInSeconds;
    	      this.requestsLimit = defaults.requestsLimit;
        }

        @CustomType.Setter
        public Builder actionDurationInSeconds(Integer actionDurationInSeconds) {
            this.actionDurationInSeconds = Objects.requireNonNull(actionDurationInSeconds);
            return this;
        }
        @CustomType.Setter
        public Builder periodInSeconds(Integer periodInSeconds) {
            this.periodInSeconds = Objects.requireNonNull(periodInSeconds);
            return this;
        }
        @CustomType.Setter
        public Builder requestsLimit(Integer requestsLimit) {
            this.requestsLimit = Objects.requireNonNull(requestsLimit);
            return this;
        }
        public GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestRateLimitingRuleConfiguration build() {
            final var o = new GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemRequestRateLimitingRuleConfiguration();
            o.actionDurationInSeconds = actionDurationInSeconds;
            o.periodInSeconds = periodInSeconds;
            o.requestsLimit = requestsLimit;
            return o;
        }
    }
}