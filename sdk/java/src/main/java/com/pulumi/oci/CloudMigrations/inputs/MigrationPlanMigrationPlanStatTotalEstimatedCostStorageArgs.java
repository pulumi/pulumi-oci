// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudMigrations.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.CloudMigrations.inputs.MigrationPlanMigrationPlanStatTotalEstimatedCostStorageVolumeArgs;
import java.lang.Double;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class MigrationPlanMigrationPlanStatTotalEstimatedCostStorageArgs extends com.pulumi.resources.ResourceArgs {

    public static final MigrationPlanMigrationPlanStatTotalEstimatedCostStorageArgs Empty = new MigrationPlanMigrationPlanStatTotalEstimatedCostStorageArgs();

    /**
     * Gigabyte storage capacity per month.
     * 
     */
    @Import(name="totalGbPerMonth")
    private @Nullable Output<Double> totalGbPerMonth;

    /**
     * @return Gigabyte storage capacity per month.
     * 
     */
    public Optional<Output<Double>> totalGbPerMonth() {
        return Optional.ofNullable(this.totalGbPerMonth);
    }

    /**
     * Gigabyte storage capacity per month by subscription
     * 
     */
    @Import(name="totalGbPerMonthBySubscription")
    private @Nullable Output<Double> totalGbPerMonthBySubscription;

    /**
     * @return Gigabyte storage capacity per month by subscription
     * 
     */
    public Optional<Output<Double>> totalGbPerMonthBySubscription() {
        return Optional.ofNullable(this.totalGbPerMonthBySubscription);
    }

    /**
     * Volume estimation
     * 
     */
    @Import(name="volumes")
    private @Nullable Output<List<MigrationPlanMigrationPlanStatTotalEstimatedCostStorageVolumeArgs>> volumes;

    /**
     * @return Volume estimation
     * 
     */
    public Optional<Output<List<MigrationPlanMigrationPlanStatTotalEstimatedCostStorageVolumeArgs>>> volumes() {
        return Optional.ofNullable(this.volumes);
    }

    private MigrationPlanMigrationPlanStatTotalEstimatedCostStorageArgs() {}

    private MigrationPlanMigrationPlanStatTotalEstimatedCostStorageArgs(MigrationPlanMigrationPlanStatTotalEstimatedCostStorageArgs $) {
        this.totalGbPerMonth = $.totalGbPerMonth;
        this.totalGbPerMonthBySubscription = $.totalGbPerMonthBySubscription;
        this.volumes = $.volumes;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MigrationPlanMigrationPlanStatTotalEstimatedCostStorageArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MigrationPlanMigrationPlanStatTotalEstimatedCostStorageArgs $;

        public Builder() {
            $ = new MigrationPlanMigrationPlanStatTotalEstimatedCostStorageArgs();
        }

        public Builder(MigrationPlanMigrationPlanStatTotalEstimatedCostStorageArgs defaults) {
            $ = new MigrationPlanMigrationPlanStatTotalEstimatedCostStorageArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param totalGbPerMonth Gigabyte storage capacity per month.
         * 
         * @return builder
         * 
         */
        public Builder totalGbPerMonth(@Nullable Output<Double> totalGbPerMonth) {
            $.totalGbPerMonth = totalGbPerMonth;
            return this;
        }

        /**
         * @param totalGbPerMonth Gigabyte storage capacity per month.
         * 
         * @return builder
         * 
         */
        public Builder totalGbPerMonth(Double totalGbPerMonth) {
            return totalGbPerMonth(Output.of(totalGbPerMonth));
        }

        /**
         * @param totalGbPerMonthBySubscription Gigabyte storage capacity per month by subscription
         * 
         * @return builder
         * 
         */
        public Builder totalGbPerMonthBySubscription(@Nullable Output<Double> totalGbPerMonthBySubscription) {
            $.totalGbPerMonthBySubscription = totalGbPerMonthBySubscription;
            return this;
        }

        /**
         * @param totalGbPerMonthBySubscription Gigabyte storage capacity per month by subscription
         * 
         * @return builder
         * 
         */
        public Builder totalGbPerMonthBySubscription(Double totalGbPerMonthBySubscription) {
            return totalGbPerMonthBySubscription(Output.of(totalGbPerMonthBySubscription));
        }

        /**
         * @param volumes Volume estimation
         * 
         * @return builder
         * 
         */
        public Builder volumes(@Nullable Output<List<MigrationPlanMigrationPlanStatTotalEstimatedCostStorageVolumeArgs>> volumes) {
            $.volumes = volumes;
            return this;
        }

        /**
         * @param volumes Volume estimation
         * 
         * @return builder
         * 
         */
        public Builder volumes(List<MigrationPlanMigrationPlanStatTotalEstimatedCostStorageVolumeArgs> volumes) {
            return volumes(Output.of(volumes));
        }

        /**
         * @param volumes Volume estimation
         * 
         * @return builder
         * 
         */
        public Builder volumes(MigrationPlanMigrationPlanStatTotalEstimatedCostStorageVolumeArgs... volumes) {
            return volumes(List.of(volumes));
        }

        public MigrationPlanMigrationPlanStatTotalEstimatedCostStorageArgs build() {
            return $;
        }
    }

}