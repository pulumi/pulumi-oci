// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.Integer;
import java.util.Objects;

@CustomType
public final class GetDomainsAuthenticationFactorSettingEndpointRestriction {
    /**
     * @return Maximum number of days until an endpoint can be trusted
     * 
     */
    private Integer maxEndpointTrustDurationInDays;
    /**
     * @return Maximum number of enrolled devices per user
     * 
     */
    private Integer maxEnrolledDevices;
    /**
     * @return An integer that represents the maximum number of failed MFA logins before an account is locked
     * 
     */
    private Integer maxIncorrectAttempts;
    /**
     * @return Max number of trusted endpoints per user
     * 
     */
    private Integer maxTrustedEndpoints;
    /**
     * @return Specify if trusted endpoints are enabled
     * 
     */
    private Boolean trustedEndpointsEnabled;

    private GetDomainsAuthenticationFactorSettingEndpointRestriction() {}
    /**
     * @return Maximum number of days until an endpoint can be trusted
     * 
     */
    public Integer maxEndpointTrustDurationInDays() {
        return this.maxEndpointTrustDurationInDays;
    }
    /**
     * @return Maximum number of enrolled devices per user
     * 
     */
    public Integer maxEnrolledDevices() {
        return this.maxEnrolledDevices;
    }
    /**
     * @return An integer that represents the maximum number of failed MFA logins before an account is locked
     * 
     */
    public Integer maxIncorrectAttempts() {
        return this.maxIncorrectAttempts;
    }
    /**
     * @return Max number of trusted endpoints per user
     * 
     */
    public Integer maxTrustedEndpoints() {
        return this.maxTrustedEndpoints;
    }
    /**
     * @return Specify if trusted endpoints are enabled
     * 
     */
    public Boolean trustedEndpointsEnabled() {
        return this.trustedEndpointsEnabled;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsAuthenticationFactorSettingEndpointRestriction defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer maxEndpointTrustDurationInDays;
        private Integer maxEnrolledDevices;
        private Integer maxIncorrectAttempts;
        private Integer maxTrustedEndpoints;
        private Boolean trustedEndpointsEnabled;
        public Builder() {}
        public Builder(GetDomainsAuthenticationFactorSettingEndpointRestriction defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.maxEndpointTrustDurationInDays = defaults.maxEndpointTrustDurationInDays;
    	      this.maxEnrolledDevices = defaults.maxEnrolledDevices;
    	      this.maxIncorrectAttempts = defaults.maxIncorrectAttempts;
    	      this.maxTrustedEndpoints = defaults.maxTrustedEndpoints;
    	      this.trustedEndpointsEnabled = defaults.trustedEndpointsEnabled;
        }

        @CustomType.Setter
        public Builder maxEndpointTrustDurationInDays(Integer maxEndpointTrustDurationInDays) {
            this.maxEndpointTrustDurationInDays = Objects.requireNonNull(maxEndpointTrustDurationInDays);
            return this;
        }
        @CustomType.Setter
        public Builder maxEnrolledDevices(Integer maxEnrolledDevices) {
            this.maxEnrolledDevices = Objects.requireNonNull(maxEnrolledDevices);
            return this;
        }
        @CustomType.Setter
        public Builder maxIncorrectAttempts(Integer maxIncorrectAttempts) {
            this.maxIncorrectAttempts = Objects.requireNonNull(maxIncorrectAttempts);
            return this;
        }
        @CustomType.Setter
        public Builder maxTrustedEndpoints(Integer maxTrustedEndpoints) {
            this.maxTrustedEndpoints = Objects.requireNonNull(maxTrustedEndpoints);
            return this;
        }
        @CustomType.Setter
        public Builder trustedEndpointsEnabled(Boolean trustedEndpointsEnabled) {
            this.trustedEndpointsEnabled = Objects.requireNonNull(trustedEndpointsEnabled);
            return this;
        }
        public GetDomainsAuthenticationFactorSettingEndpointRestriction build() {
            final var o = new GetDomainsAuthenticationFactorSettingEndpointRestriction();
            o.maxEndpointTrustDurationInDays = maxEndpointTrustDurationInDays;
            o.maxEnrolledDevices = maxEnrolledDevices;
            o.maxIncorrectAttempts = maxIncorrectAttempts;
            o.maxTrustedEndpoints = maxTrustedEndpoints;
            o.trustedEndpointsEnabled = trustedEndpointsEnabled;
            return o;
        }
    }
}