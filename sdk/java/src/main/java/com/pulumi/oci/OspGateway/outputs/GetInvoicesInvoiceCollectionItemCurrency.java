// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OspGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Double;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetInvoicesInvoiceCollectionItemCurrency {
    /**
     * @return Currency code
     * 
     */
    private final String currencyCode;
    /**
     * @return Currency symbol
     * 
     */
    private final String currencySymbol;
    /**
     * @return Name of the currency
     * 
     */
    private final String name;
    /**
     * @return Round decimal point
     * 
     */
    private final Double roundDecimalPoint;
    /**
     * @return USD conversion rate of the currency
     * 
     */
    private final Double usdConversion;

    @CustomType.Constructor
    private GetInvoicesInvoiceCollectionItemCurrency(
        @CustomType.Parameter("currencyCode") String currencyCode,
        @CustomType.Parameter("currencySymbol") String currencySymbol,
        @CustomType.Parameter("name") String name,
        @CustomType.Parameter("roundDecimalPoint") Double roundDecimalPoint,
        @CustomType.Parameter("usdConversion") Double usdConversion) {
        this.currencyCode = currencyCode;
        this.currencySymbol = currencySymbol;
        this.name = name;
        this.roundDecimalPoint = roundDecimalPoint;
        this.usdConversion = usdConversion;
    }

    /**
     * @return Currency code
     * 
     */
    public String currencyCode() {
        return this.currencyCode;
    }
    /**
     * @return Currency symbol
     * 
     */
    public String currencySymbol() {
        return this.currencySymbol;
    }
    /**
     * @return Name of the currency
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return Round decimal point
     * 
     */
    public Double roundDecimalPoint() {
        return this.roundDecimalPoint;
    }
    /**
     * @return USD conversion rate of the currency
     * 
     */
    public Double usdConversion() {
        return this.usdConversion;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInvoicesInvoiceCollectionItemCurrency defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String currencyCode;
        private String currencySymbol;
        private String name;
        private Double roundDecimalPoint;
        private Double usdConversion;

        public Builder() {
    	      // Empty
        }

        public Builder(GetInvoicesInvoiceCollectionItemCurrency defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.currencyCode = defaults.currencyCode;
    	      this.currencySymbol = defaults.currencySymbol;
    	      this.name = defaults.name;
    	      this.roundDecimalPoint = defaults.roundDecimalPoint;
    	      this.usdConversion = defaults.usdConversion;
        }

        public Builder currencyCode(String currencyCode) {
            this.currencyCode = Objects.requireNonNull(currencyCode);
            return this;
        }
        public Builder currencySymbol(String currencySymbol) {
            this.currencySymbol = Objects.requireNonNull(currencySymbol);
            return this;
        }
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public Builder roundDecimalPoint(Double roundDecimalPoint) {
            this.roundDecimalPoint = Objects.requireNonNull(roundDecimalPoint);
            return this;
        }
        public Builder usdConversion(Double usdConversion) {
            this.usdConversion = Objects.requireNonNull(usdConversion);
            return this;
        }        public GetInvoicesInvoiceCollectionItemCurrency build() {
            return new GetInvoicesInvoiceCollectionItemCurrency(currencyCode, currencySymbol, name, roundDecimalPoint, usdConversion);
        }
    }
}
