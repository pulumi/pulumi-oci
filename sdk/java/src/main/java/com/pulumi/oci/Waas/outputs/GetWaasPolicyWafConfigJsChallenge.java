// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waas.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Waas.outputs.GetWaasPolicyWafConfigJsChallengeChallengeSettings;
import com.pulumi.oci.Waas.outputs.GetWaasPolicyWafConfigJsChallengeCriteria;
import com.pulumi.oci.Waas.outputs.GetWaasPolicyWafConfigJsChallengeSetHttpHeader;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetWaasPolicyWafConfigJsChallenge {
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
     * @return When enabled, redirect responses from the origin will also be challenged. This will change HTTP 301/302 responses from origin to HTTP 200 with an HTML body containing JavaScript page redirection.
     * 
     */
    private Boolean areRedirectsChallenged;
    /**
     * @return The challenge settings if `action` is set to `BLOCK`.
     * 
     */
    private GetWaasPolicyWafConfigJsChallengeChallengeSettings challengeSettings;
    /**
     * @return When defined, the JavaScript Challenge would be applied only for the requests that matched all the listed conditions.
     * 
     */
    private List<GetWaasPolicyWafConfigJsChallengeCriteria> criterias;
    /**
     * @return The number of failed requests before taking action. If unspecified, defaults to `10`.
     * 
     */
    private Integer failureThreshold;
    /**
     * @return Enables or disables the JavaScript challenge Web Application Firewall feature.
     * 
     */
    private Boolean isEnabled;
    /**
     * @return When enabled, the user is identified not only by the IP address but also by an unique additional hash, which prevents blocking visitors with shared IP addresses.
     * 
     */
    private Boolean isNatEnabled;
    /**
     * @return Adds an additional HTTP header to requests that fail the challenge before being passed to the origin. Only applicable when the `action` is set to `DETECT`.
     * 
     */
    private GetWaasPolicyWafConfigJsChallengeSetHttpHeader setHttpHeader;

    private GetWaasPolicyWafConfigJsChallenge() {}
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
     * @return When enabled, redirect responses from the origin will also be challenged. This will change HTTP 301/302 responses from origin to HTTP 200 with an HTML body containing JavaScript page redirection.
     * 
     */
    public Boolean areRedirectsChallenged() {
        return this.areRedirectsChallenged;
    }
    /**
     * @return The challenge settings if `action` is set to `BLOCK`.
     * 
     */
    public GetWaasPolicyWafConfigJsChallengeChallengeSettings challengeSettings() {
        return this.challengeSettings;
    }
    /**
     * @return When defined, the JavaScript Challenge would be applied only for the requests that matched all the listed conditions.
     * 
     */
    public List<GetWaasPolicyWafConfigJsChallengeCriteria> criterias() {
        return this.criterias;
    }
    /**
     * @return The number of failed requests before taking action. If unspecified, defaults to `10`.
     * 
     */
    public Integer failureThreshold() {
        return this.failureThreshold;
    }
    /**
     * @return Enables or disables the JavaScript challenge Web Application Firewall feature.
     * 
     */
    public Boolean isEnabled() {
        return this.isEnabled;
    }
    /**
     * @return When enabled, the user is identified not only by the IP address but also by an unique additional hash, which prevents blocking visitors with shared IP addresses.
     * 
     */
    public Boolean isNatEnabled() {
        return this.isNatEnabled;
    }
    /**
     * @return Adds an additional HTTP header to requests that fail the challenge before being passed to the origin. Only applicable when the `action` is set to `DETECT`.
     * 
     */
    public GetWaasPolicyWafConfigJsChallengeSetHttpHeader setHttpHeader() {
        return this.setHttpHeader;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWaasPolicyWafConfigJsChallenge defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String action;
        private Integer actionExpirationInSeconds;
        private Boolean areRedirectsChallenged;
        private GetWaasPolicyWafConfigJsChallengeChallengeSettings challengeSettings;
        private List<GetWaasPolicyWafConfigJsChallengeCriteria> criterias;
        private Integer failureThreshold;
        private Boolean isEnabled;
        private Boolean isNatEnabled;
        private GetWaasPolicyWafConfigJsChallengeSetHttpHeader setHttpHeader;
        public Builder() {}
        public Builder(GetWaasPolicyWafConfigJsChallenge defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.action = defaults.action;
    	      this.actionExpirationInSeconds = defaults.actionExpirationInSeconds;
    	      this.areRedirectsChallenged = defaults.areRedirectsChallenged;
    	      this.challengeSettings = defaults.challengeSettings;
    	      this.criterias = defaults.criterias;
    	      this.failureThreshold = defaults.failureThreshold;
    	      this.isEnabled = defaults.isEnabled;
    	      this.isNatEnabled = defaults.isNatEnabled;
    	      this.setHttpHeader = defaults.setHttpHeader;
        }

        @CustomType.Setter
        public Builder action(String action) {
            this.action = Objects.requireNonNull(action);
            return this;
        }
        @CustomType.Setter
        public Builder actionExpirationInSeconds(Integer actionExpirationInSeconds) {
            this.actionExpirationInSeconds = Objects.requireNonNull(actionExpirationInSeconds);
            return this;
        }
        @CustomType.Setter
        public Builder areRedirectsChallenged(Boolean areRedirectsChallenged) {
            this.areRedirectsChallenged = Objects.requireNonNull(areRedirectsChallenged);
            return this;
        }
        @CustomType.Setter
        public Builder challengeSettings(GetWaasPolicyWafConfigJsChallengeChallengeSettings challengeSettings) {
            this.challengeSettings = Objects.requireNonNull(challengeSettings);
            return this;
        }
        @CustomType.Setter
        public Builder criterias(List<GetWaasPolicyWafConfigJsChallengeCriteria> criterias) {
            this.criterias = Objects.requireNonNull(criterias);
            return this;
        }
        public Builder criterias(GetWaasPolicyWafConfigJsChallengeCriteria... criterias) {
            return criterias(List.of(criterias));
        }
        @CustomType.Setter
        public Builder failureThreshold(Integer failureThreshold) {
            this.failureThreshold = Objects.requireNonNull(failureThreshold);
            return this;
        }
        @CustomType.Setter
        public Builder isEnabled(Boolean isEnabled) {
            this.isEnabled = Objects.requireNonNull(isEnabled);
            return this;
        }
        @CustomType.Setter
        public Builder isNatEnabled(Boolean isNatEnabled) {
            this.isNatEnabled = Objects.requireNonNull(isNatEnabled);
            return this;
        }
        @CustomType.Setter
        public Builder setHttpHeader(GetWaasPolicyWafConfigJsChallengeSetHttpHeader setHttpHeader) {
            this.setHttpHeader = Objects.requireNonNull(setHttpHeader);
            return this;
        }
        public GetWaasPolicyWafConfigJsChallenge build() {
            final var o = new GetWaasPolicyWafConfigJsChallenge();
            o.action = action;
            o.actionExpirationInSeconds = actionExpirationInSeconds;
            o.areRedirectsChallenged = areRedirectsChallenged;
            o.challengeSettings = challengeSettings;
            o.criterias = criterias;
            o.failureThreshold = failureThreshold;
            o.isEnabled = isEnabled;
            o.isNatEnabled = isNatEnabled;
            o.setHttpHeader = setHttpHeader;
            return o;
        }
    }
}