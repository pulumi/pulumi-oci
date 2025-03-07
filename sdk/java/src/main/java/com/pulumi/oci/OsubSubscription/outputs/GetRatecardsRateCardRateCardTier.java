// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsubSubscription.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetRatecardsRateCardRateCardTier {
    /**
     * @return Rate card tier net unit price
     * 
     */
    private String netUnitPrice;
    /**
     * @return Rate card tier overage price
     * 
     */
    private String overagePrice;
    /**
     * @return Rate card tier quantity range
     * 
     */
    private String upToQuantity;

    private GetRatecardsRateCardRateCardTier() {}
    /**
     * @return Rate card tier net unit price
     * 
     */
    public String netUnitPrice() {
        return this.netUnitPrice;
    }
    /**
     * @return Rate card tier overage price
     * 
     */
    public String overagePrice() {
        return this.overagePrice;
    }
    /**
     * @return Rate card tier quantity range
     * 
     */
    public String upToQuantity() {
        return this.upToQuantity;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRatecardsRateCardRateCardTier defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String netUnitPrice;
        private String overagePrice;
        private String upToQuantity;
        public Builder() {}
        public Builder(GetRatecardsRateCardRateCardTier defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.netUnitPrice = defaults.netUnitPrice;
    	      this.overagePrice = defaults.overagePrice;
    	      this.upToQuantity = defaults.upToQuantity;
        }

        @CustomType.Setter
        public Builder netUnitPrice(String netUnitPrice) {
            if (netUnitPrice == null) {
              throw new MissingRequiredPropertyException("GetRatecardsRateCardRateCardTier", "netUnitPrice");
            }
            this.netUnitPrice = netUnitPrice;
            return this;
        }
        @CustomType.Setter
        public Builder overagePrice(String overagePrice) {
            if (overagePrice == null) {
              throw new MissingRequiredPropertyException("GetRatecardsRateCardRateCardTier", "overagePrice");
            }
            this.overagePrice = overagePrice;
            return this;
        }
        @CustomType.Setter
        public Builder upToQuantity(String upToQuantity) {
            if (upToQuantity == null) {
              throw new MissingRequiredPropertyException("GetRatecardsRateCardRateCardTier", "upToQuantity");
            }
            this.upToQuantity = upToQuantity;
            return this;
        }
        public GetRatecardsRateCardRateCardTier build() {
            final var _resultValue = new GetRatecardsRateCardRateCardTier();
            _resultValue.netUnitPrice = netUnitPrice;
            _resultValue.overagePrice = overagePrice;
            _resultValue.upToQuantity = upToQuantity;
            return _resultValue;
        }
    }
}
