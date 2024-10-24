// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudMigrations.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.CloudMigrations.outputs.MigrationPlanMigrationPlanStatTotalEstimatedCostStorageVolume;
import java.lang.Double;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class MigrationPlanMigrationPlanStatTotalEstimatedCostStorage {
    /**
     * @return Gigabyte storage capacity per month.
     * 
     */
    private @Nullable Double totalGbPerMonth;
    /**
     * @return Gigabyte storage capacity per month by subscription
     * 
     */
    private @Nullable Double totalGbPerMonthBySubscription;
    /**
     * @return Volume estimation
     * 
     */
    private @Nullable List<MigrationPlanMigrationPlanStatTotalEstimatedCostStorageVolume> volumes;

    private MigrationPlanMigrationPlanStatTotalEstimatedCostStorage() {}
    /**
     * @return Gigabyte storage capacity per month.
     * 
     */
    public Optional<Double> totalGbPerMonth() {
        return Optional.ofNullable(this.totalGbPerMonth);
    }
    /**
     * @return Gigabyte storage capacity per month by subscription
     * 
     */
    public Optional<Double> totalGbPerMonthBySubscription() {
        return Optional.ofNullable(this.totalGbPerMonthBySubscription);
    }
    /**
     * @return Volume estimation
     * 
     */
    public List<MigrationPlanMigrationPlanStatTotalEstimatedCostStorageVolume> volumes() {
        return this.volumes == null ? List.of() : this.volumes;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(MigrationPlanMigrationPlanStatTotalEstimatedCostStorage defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Double totalGbPerMonth;
        private @Nullable Double totalGbPerMonthBySubscription;
        private @Nullable List<MigrationPlanMigrationPlanStatTotalEstimatedCostStorageVolume> volumes;
        public Builder() {}
        public Builder(MigrationPlanMigrationPlanStatTotalEstimatedCostStorage defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.totalGbPerMonth = defaults.totalGbPerMonth;
    	      this.totalGbPerMonthBySubscription = defaults.totalGbPerMonthBySubscription;
    	      this.volumes = defaults.volumes;
        }

        @CustomType.Setter
        public Builder totalGbPerMonth(@Nullable Double totalGbPerMonth) {

            this.totalGbPerMonth = totalGbPerMonth;
            return this;
        }
        @CustomType.Setter
        public Builder totalGbPerMonthBySubscription(@Nullable Double totalGbPerMonthBySubscription) {

            this.totalGbPerMonthBySubscription = totalGbPerMonthBySubscription;
            return this;
        }
        @CustomType.Setter
        public Builder volumes(@Nullable List<MigrationPlanMigrationPlanStatTotalEstimatedCostStorageVolume> volumes) {

            this.volumes = volumes;
            return this;
        }
        public Builder volumes(MigrationPlanMigrationPlanStatTotalEstimatedCostStorageVolume... volumes) {
            return volumes(List.of(volumes));
        }
        public MigrationPlanMigrationPlanStatTotalEstimatedCostStorage build() {
            final var _resultValue = new MigrationPlanMigrationPlanStatTotalEstimatedCostStorage();
            _resultValue.totalGbPerMonth = totalGbPerMonth;
            _resultValue.totalGbPerMonthBySubscription = totalGbPerMonthBySubscription;
            _resultValue.volumes = volumes;
            return _resultValue;
        }
    }
}
