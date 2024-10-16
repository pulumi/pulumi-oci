// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CertificatesManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetCertificateCertificateRule {
    /**
     * @return A property specifying the period of time, in days, before the certificate&#39;s targeted renewal that the process should occur. Expressed in [ISO 8601](https://en.wikipedia.org/wiki/ISO_8601#Time_intervals) format.
     * 
     */
    private String advanceRenewalPeriod;
    /**
     * @return A property specifying how often, in days, a certificate should be renewed. Expressed in [ISO 8601](https://en.wikipedia.org/wiki/ISO_8601#Time_intervals) format.
     * 
     */
    private String renewalInterval;
    /**
     * @return The type of rule.
     * 
     */
    private String ruleType;

    private GetCertificateCertificateRule() {}
    /**
     * @return A property specifying the period of time, in days, before the certificate&#39;s targeted renewal that the process should occur. Expressed in [ISO 8601](https://en.wikipedia.org/wiki/ISO_8601#Time_intervals) format.
     * 
     */
    public String advanceRenewalPeriod() {
        return this.advanceRenewalPeriod;
    }
    /**
     * @return A property specifying how often, in days, a certificate should be renewed. Expressed in [ISO 8601](https://en.wikipedia.org/wiki/ISO_8601#Time_intervals) format.
     * 
     */
    public String renewalInterval() {
        return this.renewalInterval;
    }
    /**
     * @return The type of rule.
     * 
     */
    public String ruleType() {
        return this.ruleType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetCertificateCertificateRule defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String advanceRenewalPeriod;
        private String renewalInterval;
        private String ruleType;
        public Builder() {}
        public Builder(GetCertificateCertificateRule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.advanceRenewalPeriod = defaults.advanceRenewalPeriod;
    	      this.renewalInterval = defaults.renewalInterval;
    	      this.ruleType = defaults.ruleType;
        }

        @CustomType.Setter
        public Builder advanceRenewalPeriod(String advanceRenewalPeriod) {
            if (advanceRenewalPeriod == null) {
              throw new MissingRequiredPropertyException("GetCertificateCertificateRule", "advanceRenewalPeriod");
            }
            this.advanceRenewalPeriod = advanceRenewalPeriod;
            return this;
        }
        @CustomType.Setter
        public Builder renewalInterval(String renewalInterval) {
            if (renewalInterval == null) {
              throw new MissingRequiredPropertyException("GetCertificateCertificateRule", "renewalInterval");
            }
            this.renewalInterval = renewalInterval;
            return this;
        }
        @CustomType.Setter
        public Builder ruleType(String ruleType) {
            if (ruleType == null) {
              throw new MissingRequiredPropertyException("GetCertificateCertificateRule", "ruleType");
            }
            this.ruleType = ruleType;
            return this;
        }
        public GetCertificateCertificateRule build() {
            final var _resultValue = new GetCertificateCertificateRule();
            _resultValue.advanceRenewalPeriod = advanceRenewalPeriod;
            _resultValue.renewalInterval = renewalInterval;
            _resultValue.ruleType = ruleType;
            return _resultValue;
        }
    }
}
