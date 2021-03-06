// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waas.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Waas.outputs.GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallengeChallengeSetting;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallenge {
    /**
     * @return The action to take against requests from detected bots. If unspecified, defaults to `DETECT`.
     * 
     */
    private final String action;
    /**
     * @return The number of seconds between challenges from the same IP address. If unspecified, defaults to `60`.
     * 
     */
    private final Integer actionExpirationInSeconds;
    /**
     * @return The challenge settings if `action` is set to `BLOCK`.
     * 
     */
    private final List<GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallengeChallengeSetting> challengeSettings;
    /**
     * @return The number of failed requests before taking action. If unspecified, defaults to `10`.
     * 
     */
    private final Integer failureThreshold;
    /**
     * @return The number of seconds before the failure threshold resets. If unspecified, defaults to  `60`.
     * 
     */
    private final Integer failureThresholdExpirationInSeconds;
    /**
     * @return Enables or disables the JavaScript challenge Web Application Firewall feature.
     * 
     */
    private final Boolean isEnabled;
    /**
     * @return The maximum number of IP addresses permitted with the same device fingerprint. If unspecified, defaults to `20`.
     * 
     */
    private final Integer maxAddressCount;
    /**
     * @return The number of seconds before the maximum addresses count resets. If unspecified, defaults to `60`.
     * 
     */
    private final Integer maxAddressCountExpirationInSeconds;

    @CustomType.Constructor
    private GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallenge(
        @CustomType.Parameter("action") String action,
        @CustomType.Parameter("actionExpirationInSeconds") Integer actionExpirationInSeconds,
        @CustomType.Parameter("challengeSettings") List<GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallengeChallengeSetting> challengeSettings,
        @CustomType.Parameter("failureThreshold") Integer failureThreshold,
        @CustomType.Parameter("failureThresholdExpirationInSeconds") Integer failureThresholdExpirationInSeconds,
        @CustomType.Parameter("isEnabled") Boolean isEnabled,
        @CustomType.Parameter("maxAddressCount") Integer maxAddressCount,
        @CustomType.Parameter("maxAddressCountExpirationInSeconds") Integer maxAddressCountExpirationInSeconds) {
        this.action = action;
        this.actionExpirationInSeconds = actionExpirationInSeconds;
        this.challengeSettings = challengeSettings;
        this.failureThreshold = failureThreshold;
        this.failureThresholdExpirationInSeconds = failureThresholdExpirationInSeconds;
        this.isEnabled = isEnabled;
        this.maxAddressCount = maxAddressCount;
        this.maxAddressCountExpirationInSeconds = maxAddressCountExpirationInSeconds;
    }

    /**
     * @return The action to take against requests from detected bots. If unspecified, defaults to `DETECT`.
     * 
     */
    public String action() {
        return this.action;
    }
    /**
     * @return The number of seconds between challenges from the same IP address. If unspecified, defaults to `60`.
     * 
     */
    public Integer actionExpirationInSeconds() {
        return this.actionExpirationInSeconds;
    }
    /**
     * @return The challenge settings if `action` is set to `BLOCK`.
     * 
     */
    public List<GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallengeChallengeSetting> challengeSettings() {
        return this.challengeSettings;
    }
    /**
     * @return The number of failed requests before taking action. If unspecified, defaults to `10`.
     * 
     */
    public Integer failureThreshold() {
        return this.failureThreshold;
    }
    /**
     * @return The number of seconds before the failure threshold resets. If unspecified, defaults to  `60`.
     * 
     */
    public Integer failureThresholdExpirationInSeconds() {
        return this.failureThresholdExpirationInSeconds;
    }
    /**
     * @return Enables or disables the JavaScript challenge Web Application Firewall feature.
     * 
     */
    public Boolean isEnabled() {
        return this.isEnabled;
    }
    /**
     * @return The maximum number of IP addresses permitted with the same device fingerprint. If unspecified, defaults to `20`.
     * 
     */
    public Integer maxAddressCount() {
        return this.maxAddressCount;
    }
    /**
     * @return The number of seconds before the maximum addresses count resets. If unspecified, defaults to `60`.
     * 
     */
    public Integer maxAddressCountExpirationInSeconds() {
        return this.maxAddressCountExpirationInSeconds;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallenge defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String action;
        private Integer actionExpirationInSeconds;
        private List<GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallengeChallengeSetting> challengeSettings;
        private Integer failureThreshold;
        private Integer failureThresholdExpirationInSeconds;
        private Boolean isEnabled;
        private Integer maxAddressCount;
        private Integer maxAddressCountExpirationInSeconds;

        public Builder() {
    	      // Empty
        }

        public Builder(GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallenge defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.action = defaults.action;
    	      this.actionExpirationInSeconds = defaults.actionExpirationInSeconds;
    	      this.challengeSettings = defaults.challengeSettings;
    	      this.failureThreshold = defaults.failureThreshold;
    	      this.failureThresholdExpirationInSeconds = defaults.failureThresholdExpirationInSeconds;
    	      this.isEnabled = defaults.isEnabled;
    	      this.maxAddressCount = defaults.maxAddressCount;
    	      this.maxAddressCountExpirationInSeconds = defaults.maxAddressCountExpirationInSeconds;
        }

        public Builder action(String action) {
            this.action = Objects.requireNonNull(action);
            return this;
        }
        public Builder actionExpirationInSeconds(Integer actionExpirationInSeconds) {
            this.actionExpirationInSeconds = Objects.requireNonNull(actionExpirationInSeconds);
            return this;
        }
        public Builder challengeSettings(List<GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallengeChallengeSetting> challengeSettings) {
            this.challengeSettings = Objects.requireNonNull(challengeSettings);
            return this;
        }
        public Builder challengeSettings(GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallengeChallengeSetting... challengeSettings) {
            return challengeSettings(List.of(challengeSettings));
        }
        public Builder failureThreshold(Integer failureThreshold) {
            this.failureThreshold = Objects.requireNonNull(failureThreshold);
            return this;
        }
        public Builder failureThresholdExpirationInSeconds(Integer failureThresholdExpirationInSeconds) {
            this.failureThresholdExpirationInSeconds = Objects.requireNonNull(failureThresholdExpirationInSeconds);
            return this;
        }
        public Builder isEnabled(Boolean isEnabled) {
            this.isEnabled = Objects.requireNonNull(isEnabled);
            return this;
        }
        public Builder maxAddressCount(Integer maxAddressCount) {
            this.maxAddressCount = Objects.requireNonNull(maxAddressCount);
            return this;
        }
        public Builder maxAddressCountExpirationInSeconds(Integer maxAddressCountExpirationInSeconds) {
            this.maxAddressCountExpirationInSeconds = Objects.requireNonNull(maxAddressCountExpirationInSeconds);
            return this;
        }        public GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallenge build() {
            return new GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallenge(action, actionExpirationInSeconds, challengeSettings, failureThreshold, failureThresholdExpirationInSeconds, isEnabled, maxAddressCount, maxAddressCountExpirationInSeconds);
        }
    }
}
