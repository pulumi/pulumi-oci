// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CertificatesManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class CertificateCertificateRule {
    /**
     * @return (Updatable) A property specifying the period of time, in days, before the certificate&#39;s targeted renewal that the process should occur. Expressed in [ISO 8601](https://en.wikipedia.org/wiki/ISO_8601#Time_intervals) format.
     * 
     */
    private String advanceRenewalPeriod;
    /**
     * @return (Updatable) A property specifying how often, in days, a certificate should be renewed. Expressed in [ISO 8601](https://en.wikipedia.org/wiki/ISO_8601#Time_intervals) format.
     * 
     */
    private String renewalInterval;
    /**
     * @return (Updatable) The type of rule.
     * 
     */
    private String ruleType;

    private CertificateCertificateRule() {}
    /**
     * @return (Updatable) A property specifying the period of time, in days, before the certificate&#39;s targeted renewal that the process should occur. Expressed in [ISO 8601](https://en.wikipedia.org/wiki/ISO_8601#Time_intervals) format.
     * 
     */
    public String advanceRenewalPeriod() {
        return this.advanceRenewalPeriod;
    }
    /**
     * @return (Updatable) A property specifying how often, in days, a certificate should be renewed. Expressed in [ISO 8601](https://en.wikipedia.org/wiki/ISO_8601#Time_intervals) format.
     * 
     */
    public String renewalInterval() {
        return this.renewalInterval;
    }
    /**
     * @return (Updatable) The type of rule.
     * 
     */
    public String ruleType() {
        return this.ruleType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(CertificateCertificateRule defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String advanceRenewalPeriod;
        private String renewalInterval;
        private String ruleType;
        public Builder() {}
        public Builder(CertificateCertificateRule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.advanceRenewalPeriod = defaults.advanceRenewalPeriod;
    	      this.renewalInterval = defaults.renewalInterval;
    	      this.ruleType = defaults.ruleType;
        }

        @CustomType.Setter
        public Builder advanceRenewalPeriod(String advanceRenewalPeriod) {
            this.advanceRenewalPeriod = Objects.requireNonNull(advanceRenewalPeriod);
            return this;
        }
        @CustomType.Setter
        public Builder renewalInterval(String renewalInterval) {
            this.renewalInterval = Objects.requireNonNull(renewalInterval);
            return this;
        }
        @CustomType.Setter
        public Builder ruleType(String ruleType) {
            this.ruleType = Objects.requireNonNull(ruleType);
            return this;
        }
        public CertificateCertificateRule build() {
            final var o = new CertificateCertificateRule();
            o.advanceRenewalPeriod = advanceRenewalPeriod;
            o.renewalInterval = renewalInterval;
            o.ruleType = ruleType;
            return o;
        }
    }
}