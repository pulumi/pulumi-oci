// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudMigrations.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.CloudMigrations.inputs.MigrationPlanMigrationPlanStatTotalEstimatedCostArgs;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class MigrationPlanMigrationPlanStatArgs extends com.pulumi.resources.ResourceArgs {

    public static final MigrationPlanMigrationPlanStatArgs Empty = new MigrationPlanMigrationPlanStatArgs();

    /**
     * The time when the migration plan was updated. An RFC3339 formatted datetime string.
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The time when the migration plan was updated. An RFC3339 formatted datetime string.
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    /**
     * Cost estimation description
     * 
     */
    @Import(name="totalEstimatedCosts")
    private @Nullable Output<List<MigrationPlanMigrationPlanStatTotalEstimatedCostArgs>> totalEstimatedCosts;

    /**
     * @return Cost estimation description
     * 
     */
    public Optional<Output<List<MigrationPlanMigrationPlanStatTotalEstimatedCostArgs>>> totalEstimatedCosts() {
        return Optional.ofNullable(this.totalEstimatedCosts);
    }

    /**
     * The total count of VMs in migration
     * 
     */
    @Import(name="vmCount")
    private @Nullable Output<Integer> vmCount;

    /**
     * @return The total count of VMs in migration
     * 
     */
    public Optional<Output<Integer>> vmCount() {
        return Optional.ofNullable(this.vmCount);
    }

    private MigrationPlanMigrationPlanStatArgs() {}

    private MigrationPlanMigrationPlanStatArgs(MigrationPlanMigrationPlanStatArgs $) {
        this.timeUpdated = $.timeUpdated;
        this.totalEstimatedCosts = $.totalEstimatedCosts;
        this.vmCount = $.vmCount;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MigrationPlanMigrationPlanStatArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MigrationPlanMigrationPlanStatArgs $;

        public Builder() {
            $ = new MigrationPlanMigrationPlanStatArgs();
        }

        public Builder(MigrationPlanMigrationPlanStatArgs defaults) {
            $ = new MigrationPlanMigrationPlanStatArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param timeUpdated The time when the migration plan was updated. An RFC3339 formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The time when the migration plan was updated. An RFC3339 formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        /**
         * @param totalEstimatedCosts Cost estimation description
         * 
         * @return builder
         * 
         */
        public Builder totalEstimatedCosts(@Nullable Output<List<MigrationPlanMigrationPlanStatTotalEstimatedCostArgs>> totalEstimatedCosts) {
            $.totalEstimatedCosts = totalEstimatedCosts;
            return this;
        }

        /**
         * @param totalEstimatedCosts Cost estimation description
         * 
         * @return builder
         * 
         */
        public Builder totalEstimatedCosts(List<MigrationPlanMigrationPlanStatTotalEstimatedCostArgs> totalEstimatedCosts) {
            return totalEstimatedCosts(Output.of(totalEstimatedCosts));
        }

        /**
         * @param totalEstimatedCosts Cost estimation description
         * 
         * @return builder
         * 
         */
        public Builder totalEstimatedCosts(MigrationPlanMigrationPlanStatTotalEstimatedCostArgs... totalEstimatedCosts) {
            return totalEstimatedCosts(List.of(totalEstimatedCosts));
        }

        /**
         * @param vmCount The total count of VMs in migration
         * 
         * @return builder
         * 
         */
        public Builder vmCount(@Nullable Output<Integer> vmCount) {
            $.vmCount = vmCount;
            return this;
        }

        /**
         * @param vmCount The total count of VMs in migration
         * 
         * @return builder
         * 
         */
        public Builder vmCount(Integer vmCount) {
            return vmCount(Output.of(vmCount));
        }

        public MigrationPlanMigrationPlanStatArgs build() {
            return $;
        }
    }

}