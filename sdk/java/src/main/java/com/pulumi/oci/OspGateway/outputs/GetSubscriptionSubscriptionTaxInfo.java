// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OspGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetSubscriptionSubscriptionTaxInfo {
    /**
     * @return Tax exemption reason code.
     * 
     */
    private String noTaxReasonCode;
    /**
     * @return Tax exemption reason description.
     * 
     */
    private String noTaxReasonCodeDetails;
    /**
     * @return Brazilian companies&#39; CNPJ number.
     * 
     */
    private String taxCnpj;
    /**
     * @return Tay payer identifier.
     * 
     */
    private String taxPayerId;
    /**
     * @return Tax registration number.
     * 
     */
    private String taxRegNumber;

    private GetSubscriptionSubscriptionTaxInfo() {}
    /**
     * @return Tax exemption reason code.
     * 
     */
    public String noTaxReasonCode() {
        return this.noTaxReasonCode;
    }
    /**
     * @return Tax exemption reason description.
     * 
     */
    public String noTaxReasonCodeDetails() {
        return this.noTaxReasonCodeDetails;
    }
    /**
     * @return Brazilian companies&#39; CNPJ number.
     * 
     */
    public String taxCnpj() {
        return this.taxCnpj;
    }
    /**
     * @return Tay payer identifier.
     * 
     */
    public String taxPayerId() {
        return this.taxPayerId;
    }
    /**
     * @return Tax registration number.
     * 
     */
    public String taxRegNumber() {
        return this.taxRegNumber;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSubscriptionSubscriptionTaxInfo defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String noTaxReasonCode;
        private String noTaxReasonCodeDetails;
        private String taxCnpj;
        private String taxPayerId;
        private String taxRegNumber;
        public Builder() {}
        public Builder(GetSubscriptionSubscriptionTaxInfo defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.noTaxReasonCode = defaults.noTaxReasonCode;
    	      this.noTaxReasonCodeDetails = defaults.noTaxReasonCodeDetails;
    	      this.taxCnpj = defaults.taxCnpj;
    	      this.taxPayerId = defaults.taxPayerId;
    	      this.taxRegNumber = defaults.taxRegNumber;
        }

        @CustomType.Setter
        public Builder noTaxReasonCode(String noTaxReasonCode) {
            if (noTaxReasonCode == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscriptionTaxInfo", "noTaxReasonCode");
            }
            this.noTaxReasonCode = noTaxReasonCode;
            return this;
        }
        @CustomType.Setter
        public Builder noTaxReasonCodeDetails(String noTaxReasonCodeDetails) {
            if (noTaxReasonCodeDetails == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscriptionTaxInfo", "noTaxReasonCodeDetails");
            }
            this.noTaxReasonCodeDetails = noTaxReasonCodeDetails;
            return this;
        }
        @CustomType.Setter
        public Builder taxCnpj(String taxCnpj) {
            if (taxCnpj == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscriptionTaxInfo", "taxCnpj");
            }
            this.taxCnpj = taxCnpj;
            return this;
        }
        @CustomType.Setter
        public Builder taxPayerId(String taxPayerId) {
            if (taxPayerId == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscriptionTaxInfo", "taxPayerId");
            }
            this.taxPayerId = taxPayerId;
            return this;
        }
        @CustomType.Setter
        public Builder taxRegNumber(String taxRegNumber) {
            if (taxRegNumber == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscriptionTaxInfo", "taxRegNumber");
            }
            this.taxRegNumber = taxRegNumber;
            return this;
        }
        public GetSubscriptionSubscriptionTaxInfo build() {
            final var _resultValue = new GetSubscriptionSubscriptionTaxInfo();
            _resultValue.noTaxReasonCode = noTaxReasonCode;
            _resultValue.noTaxReasonCodeDetails = noTaxReasonCodeDetails;
            _resultValue.taxCnpj = taxCnpj;
            _resultValue.taxPayerId = taxPayerId;
            _resultValue.taxRegNumber = taxRegNumber;
            return _resultValue;
        }
    }
}
