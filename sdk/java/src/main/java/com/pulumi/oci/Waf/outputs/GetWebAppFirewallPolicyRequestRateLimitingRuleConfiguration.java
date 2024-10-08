// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waf.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.util.Objects;

@CustomType
public final class GetWebAppFirewallPolicyRequestRateLimitingRuleConfiguration {
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

    private GetWebAppFirewallPolicyRequestRateLimitingRuleConfiguration() {}
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

    public static Builder builder(GetWebAppFirewallPolicyRequestRateLimitingRuleConfiguration defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer actionDurationInSeconds;
        private Integer periodInSeconds;
        private Integer requestsLimit;
        public Builder() {}
        public Builder(GetWebAppFirewallPolicyRequestRateLimitingRuleConfiguration defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.actionDurationInSeconds = defaults.actionDurationInSeconds;
    	      this.periodInSeconds = defaults.periodInSeconds;
    	      this.requestsLimit = defaults.requestsLimit;
        }

        @CustomType.Setter
        public Builder actionDurationInSeconds(Integer actionDurationInSeconds) {
            if (actionDurationInSeconds == null) {
              throw new MissingRequiredPropertyException("GetWebAppFirewallPolicyRequestRateLimitingRuleConfiguration", "actionDurationInSeconds");
            }
            this.actionDurationInSeconds = actionDurationInSeconds;
            return this;
        }
        @CustomType.Setter
        public Builder periodInSeconds(Integer periodInSeconds) {
            if (periodInSeconds == null) {
              throw new MissingRequiredPropertyException("GetWebAppFirewallPolicyRequestRateLimitingRuleConfiguration", "periodInSeconds");
            }
            this.periodInSeconds = periodInSeconds;
            return this;
        }
        @CustomType.Setter
        public Builder requestsLimit(Integer requestsLimit) {
            if (requestsLimit == null) {
              throw new MissingRequiredPropertyException("GetWebAppFirewallPolicyRequestRateLimitingRuleConfiguration", "requestsLimit");
            }
            this.requestsLimit = requestsLimit;
            return this;
        }
        public GetWebAppFirewallPolicyRequestRateLimitingRuleConfiguration build() {
            final var _resultValue = new GetWebAppFirewallPolicyRequestRateLimitingRuleConfiguration();
            _resultValue.actionDurationInSeconds = actionDurationInSeconds;
            _resultValue.periodInSeconds = periodInSeconds;
            _resultValue.requestsLimit = requestsLimit;
            return _resultValue;
        }
    }
}
