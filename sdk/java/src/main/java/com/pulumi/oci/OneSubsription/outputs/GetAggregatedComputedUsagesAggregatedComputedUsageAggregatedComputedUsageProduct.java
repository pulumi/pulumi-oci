// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OneSubsription.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetAggregatedComputedUsagesAggregatedComputedUsageAggregatedComputedUsageProduct {
    /**
     * @return Metered service billing category
     * 
     */
    private String billingCategory;
    /**
     * @return Product name
     * 
     */
    private String name;
    /**
     * @return Product part number
     * 
     */
    private String partNumber;
    /**
     * @return Product category
     * 
     */
    private String productCategory;
    /**
     * @return Product provisioning group
     * 
     */
    private String provisioningGroup;
    /**
     * @return Rate card part type of Product
     * 
     */
    private String ucmRateCardPartType;
    /**
     * @return Unit of Measure
     * 
     */
    private String unitOfMeasure;

    private GetAggregatedComputedUsagesAggregatedComputedUsageAggregatedComputedUsageProduct() {}
    /**
     * @return Metered service billing category
     * 
     */
    public String billingCategory() {
        return this.billingCategory;
    }
    /**
     * @return Product name
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return Product part number
     * 
     */
    public String partNumber() {
        return this.partNumber;
    }
    /**
     * @return Product category
     * 
     */
    public String productCategory() {
        return this.productCategory;
    }
    /**
     * @return Product provisioning group
     * 
     */
    public String provisioningGroup() {
        return this.provisioningGroup;
    }
    /**
     * @return Rate card part type of Product
     * 
     */
    public String ucmRateCardPartType() {
        return this.ucmRateCardPartType;
    }
    /**
     * @return Unit of Measure
     * 
     */
    public String unitOfMeasure() {
        return this.unitOfMeasure;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAggregatedComputedUsagesAggregatedComputedUsageAggregatedComputedUsageProduct defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String billingCategory;
        private String name;
        private String partNumber;
        private String productCategory;
        private String provisioningGroup;
        private String ucmRateCardPartType;
        private String unitOfMeasure;
        public Builder() {}
        public Builder(GetAggregatedComputedUsagesAggregatedComputedUsageAggregatedComputedUsageProduct defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.billingCategory = defaults.billingCategory;
    	      this.name = defaults.name;
    	      this.partNumber = defaults.partNumber;
    	      this.productCategory = defaults.productCategory;
    	      this.provisioningGroup = defaults.provisioningGroup;
    	      this.ucmRateCardPartType = defaults.ucmRateCardPartType;
    	      this.unitOfMeasure = defaults.unitOfMeasure;
        }

        @CustomType.Setter
        public Builder billingCategory(String billingCategory) {
            this.billingCategory = Objects.requireNonNull(billingCategory);
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        @CustomType.Setter
        public Builder partNumber(String partNumber) {
            this.partNumber = Objects.requireNonNull(partNumber);
            return this;
        }
        @CustomType.Setter
        public Builder productCategory(String productCategory) {
            this.productCategory = Objects.requireNonNull(productCategory);
            return this;
        }
        @CustomType.Setter
        public Builder provisioningGroup(String provisioningGroup) {
            this.provisioningGroup = Objects.requireNonNull(provisioningGroup);
            return this;
        }
        @CustomType.Setter
        public Builder ucmRateCardPartType(String ucmRateCardPartType) {
            this.ucmRateCardPartType = Objects.requireNonNull(ucmRateCardPartType);
            return this;
        }
        @CustomType.Setter
        public Builder unitOfMeasure(String unitOfMeasure) {
            this.unitOfMeasure = Objects.requireNonNull(unitOfMeasure);
            return this;
        }
        public GetAggregatedComputedUsagesAggregatedComputedUsageAggregatedComputedUsageProduct build() {
            final var o = new GetAggregatedComputedUsagesAggregatedComputedUsageAggregatedComputedUsageProduct();
            o.billingCategory = billingCategory;
            o.name = name;
            o.partNumber = partNumber;
            o.productCategory = productCategory;
            o.provisioningGroup = provisioningGroup;
            o.ucmRateCardPartType = ucmRateCardPartType;
            o.unitOfMeasure = unitOfMeasure;
            return o;
        }
    }
}