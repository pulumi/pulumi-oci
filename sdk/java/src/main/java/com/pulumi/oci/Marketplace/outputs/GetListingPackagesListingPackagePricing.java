// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Marketplace.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Marketplace.outputs.GetListingPackagesListingPackagePricingInternationalMarketPrice;
import java.lang.Double;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetListingPackagesListingPackagePricing {
    /**
     * @return The currency of the pricing model.
     * 
     */
    private final String currency;
    /**
     * @return The model for international market pricing.
     * 
     */
    private final List<GetListingPackagesListingPackagePricingInternationalMarketPrice> internationalMarketPrices;
    /**
     * @return The type of pricing for a PAYGO model, eg PER_OCPU_LINEAR, PER_OCPU_MIN_BILLING, PER_INSTANCE.  Null if type is not PAYGO.
     * 
     */
    private final String payGoStrategy;
    /**
     * @return The pricing rate.
     * 
     */
    private final Double rate;
    /**
     * @return The type of the pricing model.
     * 
     */
    private final String type;

    @CustomType.Constructor
    private GetListingPackagesListingPackagePricing(
        @CustomType.Parameter("currency") String currency,
        @CustomType.Parameter("internationalMarketPrices") List<GetListingPackagesListingPackagePricingInternationalMarketPrice> internationalMarketPrices,
        @CustomType.Parameter("payGoStrategy") String payGoStrategy,
        @CustomType.Parameter("rate") Double rate,
        @CustomType.Parameter("type") String type) {
        this.currency = currency;
        this.internationalMarketPrices = internationalMarketPrices;
        this.payGoStrategy = payGoStrategy;
        this.rate = rate;
        this.type = type;
    }

    /**
     * @return The currency of the pricing model.
     * 
     */
    public String currency() {
        return this.currency;
    }
    /**
     * @return The model for international market pricing.
     * 
     */
    public List<GetListingPackagesListingPackagePricingInternationalMarketPrice> internationalMarketPrices() {
        return this.internationalMarketPrices;
    }
    /**
     * @return The type of pricing for a PAYGO model, eg PER_OCPU_LINEAR, PER_OCPU_MIN_BILLING, PER_INSTANCE.  Null if type is not PAYGO.
     * 
     */
    public String payGoStrategy() {
        return this.payGoStrategy;
    }
    /**
     * @return The pricing rate.
     * 
     */
    public Double rate() {
        return this.rate;
    }
    /**
     * @return The type of the pricing model.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetListingPackagesListingPackagePricing defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String currency;
        private List<GetListingPackagesListingPackagePricingInternationalMarketPrice> internationalMarketPrices;
        private String payGoStrategy;
        private Double rate;
        private String type;

        public Builder() {
    	      // Empty
        }

        public Builder(GetListingPackagesListingPackagePricing defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.currency = defaults.currency;
    	      this.internationalMarketPrices = defaults.internationalMarketPrices;
    	      this.payGoStrategy = defaults.payGoStrategy;
    	      this.rate = defaults.rate;
    	      this.type = defaults.type;
        }

        public Builder currency(String currency) {
            this.currency = Objects.requireNonNull(currency);
            return this;
        }
        public Builder internationalMarketPrices(List<GetListingPackagesListingPackagePricingInternationalMarketPrice> internationalMarketPrices) {
            this.internationalMarketPrices = Objects.requireNonNull(internationalMarketPrices);
            return this;
        }
        public Builder internationalMarketPrices(GetListingPackagesListingPackagePricingInternationalMarketPrice... internationalMarketPrices) {
            return internationalMarketPrices(List.of(internationalMarketPrices));
        }
        public Builder payGoStrategy(String payGoStrategy) {
            this.payGoStrategy = Objects.requireNonNull(payGoStrategy);
            return this;
        }
        public Builder rate(Double rate) {
            this.rate = Objects.requireNonNull(rate);
            return this;
        }
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }        public GetListingPackagesListingPackagePricing build() {
            return new GetListingPackagesListingPackagePricing(currency, internationalMarketPrices, payGoStrategy, rate, type);
        }
    }
}
