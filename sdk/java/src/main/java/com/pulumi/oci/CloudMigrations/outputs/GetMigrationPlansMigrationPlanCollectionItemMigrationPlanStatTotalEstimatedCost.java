// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudMigrations.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.CloudMigrations.outputs.GetMigrationPlansMigrationPlanCollectionItemMigrationPlanStatTotalEstimatedCostCompute;
import com.pulumi.oci.CloudMigrations.outputs.GetMigrationPlansMigrationPlanCollectionItemMigrationPlanStatTotalEstimatedCostOsImage;
import com.pulumi.oci.CloudMigrations.outputs.GetMigrationPlansMigrationPlanCollectionItemMigrationPlanStatTotalEstimatedCostStorage;
import java.lang.Double;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetMigrationPlansMigrationPlanCollectionItemMigrationPlanStatTotalEstimatedCost {
    /**
     * @return Cost estimation for compute
     * 
     */
    private List<GetMigrationPlansMigrationPlanCollectionItemMigrationPlanStatTotalEstimatedCostCompute> computes;
    /**
     * @return Currency code in the ISO format.
     * 
     */
    private String currencyCode;
    /**
     * @return Cost estimation for the OS image.
     * 
     */
    private List<GetMigrationPlansMigrationPlanCollectionItemMigrationPlanStatTotalEstimatedCostOsImage> osImages;
    /**
     * @return Cost estimation for storage
     * 
     */
    private List<GetMigrationPlansMigrationPlanCollectionItemMigrationPlanStatTotalEstimatedCostStorage> storages;
    /**
     * @return Subscription ID
     * 
     */
    private String subscriptionId;
    /**
     * @return Total estimation per month
     * 
     */
    private Double totalEstimationPerMonth;
    /**
     * @return Total estimation per month by subscription.
     * 
     */
    private Double totalEstimationPerMonthBySubscription;

    private GetMigrationPlansMigrationPlanCollectionItemMigrationPlanStatTotalEstimatedCost() {}
    /**
     * @return Cost estimation for compute
     * 
     */
    public List<GetMigrationPlansMigrationPlanCollectionItemMigrationPlanStatTotalEstimatedCostCompute> computes() {
        return this.computes;
    }
    /**
     * @return Currency code in the ISO format.
     * 
     */
    public String currencyCode() {
        return this.currencyCode;
    }
    /**
     * @return Cost estimation for the OS image.
     * 
     */
    public List<GetMigrationPlansMigrationPlanCollectionItemMigrationPlanStatTotalEstimatedCostOsImage> osImages() {
        return this.osImages;
    }
    /**
     * @return Cost estimation for storage
     * 
     */
    public List<GetMigrationPlansMigrationPlanCollectionItemMigrationPlanStatTotalEstimatedCostStorage> storages() {
        return this.storages;
    }
    /**
     * @return Subscription ID
     * 
     */
    public String subscriptionId() {
        return this.subscriptionId;
    }
    /**
     * @return Total estimation per month
     * 
     */
    public Double totalEstimationPerMonth() {
        return this.totalEstimationPerMonth;
    }
    /**
     * @return Total estimation per month by subscription.
     * 
     */
    public Double totalEstimationPerMonthBySubscription() {
        return this.totalEstimationPerMonthBySubscription;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMigrationPlansMigrationPlanCollectionItemMigrationPlanStatTotalEstimatedCost defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetMigrationPlansMigrationPlanCollectionItemMigrationPlanStatTotalEstimatedCostCompute> computes;
        private String currencyCode;
        private List<GetMigrationPlansMigrationPlanCollectionItemMigrationPlanStatTotalEstimatedCostOsImage> osImages;
        private List<GetMigrationPlansMigrationPlanCollectionItemMigrationPlanStatTotalEstimatedCostStorage> storages;
        private String subscriptionId;
        private Double totalEstimationPerMonth;
        private Double totalEstimationPerMonthBySubscription;
        public Builder() {}
        public Builder(GetMigrationPlansMigrationPlanCollectionItemMigrationPlanStatTotalEstimatedCost defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.computes = defaults.computes;
    	      this.currencyCode = defaults.currencyCode;
    	      this.osImages = defaults.osImages;
    	      this.storages = defaults.storages;
    	      this.subscriptionId = defaults.subscriptionId;
    	      this.totalEstimationPerMonth = defaults.totalEstimationPerMonth;
    	      this.totalEstimationPerMonthBySubscription = defaults.totalEstimationPerMonthBySubscription;
        }

        @CustomType.Setter
        public Builder computes(List<GetMigrationPlansMigrationPlanCollectionItemMigrationPlanStatTotalEstimatedCostCompute> computes) {
            this.computes = Objects.requireNonNull(computes);
            return this;
        }
        public Builder computes(GetMigrationPlansMigrationPlanCollectionItemMigrationPlanStatTotalEstimatedCostCompute... computes) {
            return computes(List.of(computes));
        }
        @CustomType.Setter
        public Builder currencyCode(String currencyCode) {
            this.currencyCode = Objects.requireNonNull(currencyCode);
            return this;
        }
        @CustomType.Setter
        public Builder osImages(List<GetMigrationPlansMigrationPlanCollectionItemMigrationPlanStatTotalEstimatedCostOsImage> osImages) {
            this.osImages = Objects.requireNonNull(osImages);
            return this;
        }
        public Builder osImages(GetMigrationPlansMigrationPlanCollectionItemMigrationPlanStatTotalEstimatedCostOsImage... osImages) {
            return osImages(List.of(osImages));
        }
        @CustomType.Setter
        public Builder storages(List<GetMigrationPlansMigrationPlanCollectionItemMigrationPlanStatTotalEstimatedCostStorage> storages) {
            this.storages = Objects.requireNonNull(storages);
            return this;
        }
        public Builder storages(GetMigrationPlansMigrationPlanCollectionItemMigrationPlanStatTotalEstimatedCostStorage... storages) {
            return storages(List.of(storages));
        }
        @CustomType.Setter
        public Builder subscriptionId(String subscriptionId) {
            this.subscriptionId = Objects.requireNonNull(subscriptionId);
            return this;
        }
        @CustomType.Setter
        public Builder totalEstimationPerMonth(Double totalEstimationPerMonth) {
            this.totalEstimationPerMonth = Objects.requireNonNull(totalEstimationPerMonth);
            return this;
        }
        @CustomType.Setter
        public Builder totalEstimationPerMonthBySubscription(Double totalEstimationPerMonthBySubscription) {
            this.totalEstimationPerMonthBySubscription = Objects.requireNonNull(totalEstimationPerMonthBySubscription);
            return this;
        }
        public GetMigrationPlansMigrationPlanCollectionItemMigrationPlanStatTotalEstimatedCost build() {
            final var o = new GetMigrationPlansMigrationPlanCollectionItemMigrationPlanStatTotalEstimatedCost();
            o.computes = computes;
            o.currencyCode = currencyCode;
            o.osImages = osImages;
            o.storages = storages;
            o.subscriptionId = subscriptionId;
            o.totalEstimationPerMonth = totalEstimationPerMonth;
            o.totalEstimationPerMonthBySubscription = totalEstimationPerMonthBySubscription;
            return o;
        }
    }
}