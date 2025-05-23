// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudMigrations.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.CloudMigrations.outputs.GetMigrationPlanMigrationPlanStatTotalEstimatedCostStorageVolume;
import java.lang.Double;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetMigrationPlanMigrationPlanStatTotalEstimatedCostStorage {
    /**
     * @return Gigabyte storage capacity per month.
     * 
     */
    private Double totalGbPerMonth;
    /**
     * @return Gigabyte storage capacity per month by subscription
     * 
     */
    private Double totalGbPerMonthBySubscription;
    /**
     * @return Volume estimation
     * 
     */
    private List<GetMigrationPlanMigrationPlanStatTotalEstimatedCostStorageVolume> volumes;

    private GetMigrationPlanMigrationPlanStatTotalEstimatedCostStorage() {}
    /**
     * @return Gigabyte storage capacity per month.
     * 
     */
    public Double totalGbPerMonth() {
        return this.totalGbPerMonth;
    }
    /**
     * @return Gigabyte storage capacity per month by subscription
     * 
     */
    public Double totalGbPerMonthBySubscription() {
        return this.totalGbPerMonthBySubscription;
    }
    /**
     * @return Volume estimation
     * 
     */
    public List<GetMigrationPlanMigrationPlanStatTotalEstimatedCostStorageVolume> volumes() {
        return this.volumes;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMigrationPlanMigrationPlanStatTotalEstimatedCostStorage defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Double totalGbPerMonth;
        private Double totalGbPerMonthBySubscription;
        private List<GetMigrationPlanMigrationPlanStatTotalEstimatedCostStorageVolume> volumes;
        public Builder() {}
        public Builder(GetMigrationPlanMigrationPlanStatTotalEstimatedCostStorage defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.totalGbPerMonth = defaults.totalGbPerMonth;
    	      this.totalGbPerMonthBySubscription = defaults.totalGbPerMonthBySubscription;
    	      this.volumes = defaults.volumes;
        }

        @CustomType.Setter
        public Builder totalGbPerMonth(Double totalGbPerMonth) {
            if (totalGbPerMonth == null) {
              throw new MissingRequiredPropertyException("GetMigrationPlanMigrationPlanStatTotalEstimatedCostStorage", "totalGbPerMonth");
            }
            this.totalGbPerMonth = totalGbPerMonth;
            return this;
        }
        @CustomType.Setter
        public Builder totalGbPerMonthBySubscription(Double totalGbPerMonthBySubscription) {
            if (totalGbPerMonthBySubscription == null) {
              throw new MissingRequiredPropertyException("GetMigrationPlanMigrationPlanStatTotalEstimatedCostStorage", "totalGbPerMonthBySubscription");
            }
            this.totalGbPerMonthBySubscription = totalGbPerMonthBySubscription;
            return this;
        }
        @CustomType.Setter
        public Builder volumes(List<GetMigrationPlanMigrationPlanStatTotalEstimatedCostStorageVolume> volumes) {
            if (volumes == null) {
              throw new MissingRequiredPropertyException("GetMigrationPlanMigrationPlanStatTotalEstimatedCostStorage", "volumes");
            }
            this.volumes = volumes;
            return this;
        }
        public Builder volumes(GetMigrationPlanMigrationPlanStatTotalEstimatedCostStorageVolume... volumes) {
            return volumes(List.of(volumes));
        }
        public GetMigrationPlanMigrationPlanStatTotalEstimatedCostStorage build() {
            final var _resultValue = new GetMigrationPlanMigrationPlanStatTotalEstimatedCostStorage();
            _resultValue.totalGbPerMonth = totalGbPerMonth;
            _resultValue.totalGbPerMonthBySubscription = totalGbPerMonthBySubscription;
            _resultValue.volumes = volumes;
            return _resultValue;
        }
    }
}
