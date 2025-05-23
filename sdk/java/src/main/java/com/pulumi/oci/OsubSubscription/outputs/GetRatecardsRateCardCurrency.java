// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsubSubscription.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetRatecardsRateCardCurrency {
    /**
     * @return Currency Code
     * 
     */
    private String isoCode;
    /**
     * @return Product name
     * 
     */
    private String name;
    /**
     * @return Standard Precision of the Currency
     * 
     */
    private String stdPrecision;

    private GetRatecardsRateCardCurrency() {}
    /**
     * @return Currency Code
     * 
     */
    public String isoCode() {
        return this.isoCode;
    }
    /**
     * @return Product name
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return Standard Precision of the Currency
     * 
     */
    public String stdPrecision() {
        return this.stdPrecision;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRatecardsRateCardCurrency defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String isoCode;
        private String name;
        private String stdPrecision;
        public Builder() {}
        public Builder(GetRatecardsRateCardCurrency defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.isoCode = defaults.isoCode;
    	      this.name = defaults.name;
    	      this.stdPrecision = defaults.stdPrecision;
        }

        @CustomType.Setter
        public Builder isoCode(String isoCode) {
            if (isoCode == null) {
              throw new MissingRequiredPropertyException("GetRatecardsRateCardCurrency", "isoCode");
            }
            this.isoCode = isoCode;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetRatecardsRateCardCurrency", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder stdPrecision(String stdPrecision) {
            if (stdPrecision == null) {
              throw new MissingRequiredPropertyException("GetRatecardsRateCardCurrency", "stdPrecision");
            }
            this.stdPrecision = stdPrecision;
            return this;
        }
        public GetRatecardsRateCardCurrency build() {
            final var _resultValue = new GetRatecardsRateCardCurrency();
            _resultValue.isoCode = isoCode;
            _resultValue.name = name;
            _resultValue.stdPrecision = stdPrecision;
            return _resultValue;
        }
    }
}
