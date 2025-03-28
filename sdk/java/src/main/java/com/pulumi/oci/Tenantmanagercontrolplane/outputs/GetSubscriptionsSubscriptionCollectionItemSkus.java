// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Tenantmanagercontrolplane.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetSubscriptionsSubscriptionCollectionItemSkus {
    /**
     * @return Description of the stock units.
     * 
     */
    private String description;
    /**
     * @return Date and time when the SKU ended.
     * 
     */
    private String endDate;
    /**
     * @return Sales order line identifier.
     * 
     */
    private String gsiOrderLineId;
    /**
     * @return Specifies if an additional test instance can be provisioned by the SaaS application.
     * 
     */
    private Boolean isAdditionalInstance;
    /**
     * @return Specifies if the SKU is considered as a parent or child.
     * 
     */
    private Boolean isBaseServiceComponent;
    /**
     * @return Description of the covered product belonging to this SKU.
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
     * @return Stock Keeping Unit (SKU) ID.
     * 
     */
    private String sku;
    /**
     * @return Subscription start time.
     * 
     */
    private String startDate;

    private GetSubscriptionsSubscriptionCollectionItemSkus() {}
    /**
     * @return Description of the stock units.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return Date and time when the SKU ended.
     * 
     */
    public String endDate() {
        return this.endDate;
    }
    /**
     * @return Sales order line identifier.
     * 
     */
    public String gsiOrderLineId() {
        return this.gsiOrderLineId;
    }
    /**
     * @return Specifies if an additional test instance can be provisioned by the SaaS application.
     * 
     */
    public Boolean isAdditionalInstance() {
        return this.isAdditionalInstance;
    }
    /**
     * @return Specifies if the SKU is considered as a parent or child.
     * 
     */
    public Boolean isBaseServiceComponent() {
        return this.isBaseServiceComponent;
    }
    /**
     * @return Description of the covered product belonging to this SKU.
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
     * @return Stock Keeping Unit (SKU) ID.
     * 
     */
    public String sku() {
        return this.sku;
    }
    /**
     * @return Subscription start time.
     * 
     */
    public String startDate() {
        return this.startDate;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSubscriptionsSubscriptionCollectionItemSkus defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String description;
        private String endDate;
        private String gsiOrderLineId;
        private Boolean isAdditionalInstance;
        private Boolean isBaseServiceComponent;
        private String licensePartDescription;
        private String metricName;
        private Integer quantity;
        private String sku;
        private String startDate;
        public Builder() {}
        public Builder(GetSubscriptionsSubscriptionCollectionItemSkus defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.description = defaults.description;
    	      this.endDate = defaults.endDate;
    	      this.gsiOrderLineId = defaults.gsiOrderLineId;
    	      this.isAdditionalInstance = defaults.isAdditionalInstance;
    	      this.isBaseServiceComponent = defaults.isBaseServiceComponent;
    	      this.licensePartDescription = defaults.licensePartDescription;
    	      this.metricName = defaults.metricName;
    	      this.quantity = defaults.quantity;
    	      this.sku = defaults.sku;
    	      this.startDate = defaults.startDate;
        }

        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionsSubscriptionCollectionItemSkus", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder endDate(String endDate) {
            if (endDate == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionsSubscriptionCollectionItemSkus", "endDate");
            }
            this.endDate = endDate;
            return this;
        }
        @CustomType.Setter
        public Builder gsiOrderLineId(String gsiOrderLineId) {
            if (gsiOrderLineId == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionsSubscriptionCollectionItemSkus", "gsiOrderLineId");
            }
            this.gsiOrderLineId = gsiOrderLineId;
            return this;
        }
        @CustomType.Setter
        public Builder isAdditionalInstance(Boolean isAdditionalInstance) {
            if (isAdditionalInstance == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionsSubscriptionCollectionItemSkus", "isAdditionalInstance");
            }
            this.isAdditionalInstance = isAdditionalInstance;
            return this;
        }
        @CustomType.Setter
        public Builder isBaseServiceComponent(Boolean isBaseServiceComponent) {
            if (isBaseServiceComponent == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionsSubscriptionCollectionItemSkus", "isBaseServiceComponent");
            }
            this.isBaseServiceComponent = isBaseServiceComponent;
            return this;
        }
        @CustomType.Setter
        public Builder licensePartDescription(String licensePartDescription) {
            if (licensePartDescription == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionsSubscriptionCollectionItemSkus", "licensePartDescription");
            }
            this.licensePartDescription = licensePartDescription;
            return this;
        }
        @CustomType.Setter
        public Builder metricName(String metricName) {
            if (metricName == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionsSubscriptionCollectionItemSkus", "metricName");
            }
            this.metricName = metricName;
            return this;
        }
        @CustomType.Setter
        public Builder quantity(Integer quantity) {
            if (quantity == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionsSubscriptionCollectionItemSkus", "quantity");
            }
            this.quantity = quantity;
            return this;
        }
        @CustomType.Setter
        public Builder sku(String sku) {
            if (sku == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionsSubscriptionCollectionItemSkus", "sku");
            }
            this.sku = sku;
            return this;
        }
        @CustomType.Setter
        public Builder startDate(String startDate) {
            if (startDate == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionsSubscriptionCollectionItemSkus", "startDate");
            }
            this.startDate = startDate;
            return this;
        }
        public GetSubscriptionsSubscriptionCollectionItemSkus build() {
            final var _resultValue = new GetSubscriptionsSubscriptionCollectionItemSkus();
            _resultValue.description = description;
            _resultValue.endDate = endDate;
            _resultValue.gsiOrderLineId = gsiOrderLineId;
            _resultValue.isAdditionalInstance = isAdditionalInstance;
            _resultValue.isBaseServiceComponent = isBaseServiceComponent;
            _resultValue.licensePartDescription = licensePartDescription;
            _resultValue.metricName = metricName;
            _resultValue.quantity = quantity;
            _resultValue.sku = sku;
            _resultValue.startDate = startDate;
            return _resultValue;
        }
    }
}
