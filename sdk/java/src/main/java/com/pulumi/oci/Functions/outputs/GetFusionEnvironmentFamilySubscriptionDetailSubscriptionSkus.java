// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Functions.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetFusionEnvironmentFamilySubscriptionDetailSubscriptionSkus {
    /**
     * @return Description of the stock units.
     * 
     */
    private String description;
    /**
     * @return Description of the covered product belonging to this Sku.
     * 
     */
    private String licensePartDescription;
    /**
     * @return Base metric for billing the service.
     * 
     */
    private String metricName;
    /**
     * @return Quantity of the stock units.
     * 
     */
    private Integer quantity;
    /**
     * @return Stock keeping unit id.
     * 
     */
    private String sku;

    private GetFusionEnvironmentFamilySubscriptionDetailSubscriptionSkus() {}
    /**
     * @return Description of the stock units.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return Description of the covered product belonging to this Sku.
     * 
     */
    public String licensePartDescription() {
        return this.licensePartDescription;
    }
    /**
     * @return Base metric for billing the service.
     * 
     */
    public String metricName() {
        return this.metricName;
    }
    /**
     * @return Quantity of the stock units.
     * 
     */
    public Integer quantity() {
        return this.quantity;
    }
    /**
     * @return Stock keeping unit id.
     * 
     */
    public String sku() {
        return this.sku;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFusionEnvironmentFamilySubscriptionDetailSubscriptionSkus defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String description;
        private String licensePartDescription;
        private String metricName;
        private Integer quantity;
        private String sku;
        public Builder() {}
        public Builder(GetFusionEnvironmentFamilySubscriptionDetailSubscriptionSkus defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.description = defaults.description;
    	      this.licensePartDescription = defaults.licensePartDescription;
    	      this.metricName = defaults.metricName;
    	      this.quantity = defaults.quantity;
    	      this.sku = defaults.sku;
        }

        @CustomType.Setter
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        @CustomType.Setter
        public Builder licensePartDescription(String licensePartDescription) {
            this.licensePartDescription = Objects.requireNonNull(licensePartDescription);
            return this;
        }
        @CustomType.Setter
        public Builder metricName(String metricName) {
            this.metricName = Objects.requireNonNull(metricName);
            return this;
        }
        @CustomType.Setter
        public Builder quantity(Integer quantity) {
            this.quantity = Objects.requireNonNull(quantity);
            return this;
        }
        @CustomType.Setter
        public Builder sku(String sku) {
            this.sku = Objects.requireNonNull(sku);
            return this;
        }
        public GetFusionEnvironmentFamilySubscriptionDetailSubscriptionSkus build() {
            final var o = new GetFusionEnvironmentFamilySubscriptionDetailSubscriptionSkus();
            o.description = description;
            o.licensePartDescription = licensePartDescription;
            o.metricName = metricName;
            o.quantity = quantity;
            o.sku = sku;
            return o;
        }
    }
}