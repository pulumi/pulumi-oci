// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waas.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
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
    private String action;
    /**
     * @return The number of seconds between challenges from the same IP address. If unspecified, defaults to `60`.
     * 
     */
    private Integer actionExpirationInSeconds;
    /**
     * @return The challenge settings if `action` is set to `BLOCK`.
     * 
     */
    private List<GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallengeChallengeSetting> challengeSettings;
    /**
     * @return The number of failed requests before taking action. If unspecified, defaults to `10`.
     * 
     */
    private Integer failureThreshold;
    /**
     * @return The number of seconds before the failure threshold resets. If unspecified, defaults to  `60`.
     * 
     */
    private Integer failureThresholdExpirationInSeconds;
    /**
     * @return Enables or disables the JavaScript challenge Web Application Firewall feature.
     * 
     */
    private Boolean isEnabled;
    /**
     * @return The maximum number of IP addresses permitted with the same device fingerprint. If unspecified, defaults to `20`.
     * 
     */
    private Integer maxAddressCount;
    /**
     * @return The number of seconds before the maximum addresses count resets. If unspecified, defaults to `60`.
     * 
     */
    private Integer maxAddressCountExpirationInSeconds;

    private GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallenge() {}
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
    @CustomType.Builder
    public static final class Builder {
        private String action;
        private Integer actionExpirationInSeconds;
        private List<GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallengeChallengeSetting> challengeSettings;
        private Integer failureThreshold;
        private Integer failureThresholdExpirationInSeconds;
        private Boolean isEnabled;
        private Integer maxAddressCount;
        private Integer maxAddressCountExpirationInSeconds;
        public Builder() {}
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

        @CustomType.Setter
        public Builder action(String action) {
            if (action == null) {
              throw new MissingRequiredPropertyException("GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallenge", "action");
            }
            this.action = action;
            return this;
        }
        @CustomType.Setter
        public Builder actionExpirationInSeconds(Integer actionExpirationInSeconds) {
            if (actionExpirationInSeconds == null) {
              throw new MissingRequiredPropertyException("GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallenge", "actionExpirationInSeconds");
            }
            this.actionExpirationInSeconds = actionExpirationInSeconds;
            return this;
        }
        @CustomType.Setter
        public Builder challengeSettings(List<GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallengeChallengeSetting> challengeSettings) {
            if (challengeSettings == null) {
              throw new MissingRequiredPropertyException("GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallenge", "challengeSettings");
            }
            this.challengeSettings = challengeSettings;
            return this;
        }
        public Builder challengeSettings(GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallengeChallengeSetting... challengeSettings) {
            return challengeSettings(List.of(challengeSettings));
        }
        @CustomType.Setter
        public Builder failureThreshold(Integer failureThreshold) {
            if (failureThreshold == null) {
              throw new MissingRequiredPropertyException("GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallenge", "failureThreshold");
            }
            this.failureThreshold = failureThreshold;
            return this;
        }
        @CustomType.Setter
        public Builder failureThresholdExpirationInSeconds(Integer failureThresholdExpirationInSeconds) {
            if (failureThresholdExpirationInSeconds == null) {
              throw new MissingRequiredPropertyException("GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallenge", "failureThresholdExpirationInSeconds");
            }
            this.failureThresholdExpirationInSeconds = failureThresholdExpirationInSeconds;
            return this;
        }
        @CustomType.Setter
        public Builder isEnabled(Boolean isEnabled) {
            if (isEnabled == null) {
              throw new MissingRequiredPropertyException("GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallenge", "isEnabled");
            }
            this.isEnabled = isEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder maxAddressCount(Integer maxAddressCount) {
            if (maxAddressCount == null) {
              throw new MissingRequiredPropertyException("GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallenge", "maxAddressCount");
            }
            this.maxAddressCount = maxAddressCount;
            return this;
        }
        @CustomType.Setter
        public Builder maxAddressCountExpirationInSeconds(Integer maxAddressCountExpirationInSeconds) {
            if (maxAddressCountExpirationInSeconds == null) {
              throw new MissingRequiredPropertyException("GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallenge", "maxAddressCountExpirationInSeconds");
            }
            this.maxAddressCountExpirationInSeconds = maxAddressCountExpirationInSeconds;
            return this;
        }
        public GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallenge build() {
            final var _resultValue = new GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallenge();
            _resultValue.action = action;
            _resultValue.actionExpirationInSeconds = actionExpirationInSeconds;
            _resultValue.challengeSettings = challengeSettings;
            _resultValue.failureThreshold = failureThreshold;
            _resultValue.failureThresholdExpirationInSeconds = failureThresholdExpirationInSeconds;
            _resultValue.isEnabled = isEnabled;
            _resultValue.maxAddressCount = maxAddressCount;
            _resultValue.maxAddressCountExpirationInSeconds = maxAddressCountExpirationInSeconds;
            return _resultValue;
        }
    }
}
