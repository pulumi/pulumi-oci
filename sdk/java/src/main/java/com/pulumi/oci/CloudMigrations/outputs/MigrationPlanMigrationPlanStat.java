// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudMigrations.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.CloudMigrations.outputs.MigrationPlanMigrationPlanStatTotalEstimatedCost;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class MigrationPlanMigrationPlanStat {
    /**
     * @return The time when the migration plan was updated. An RFC3339 formatted datetime string.
     * 
     */
    private @Nullable String timeUpdated;
    /**
     * @return Cost estimation description
     * 
     */
    private @Nullable List<MigrationPlanMigrationPlanStatTotalEstimatedCost> totalEstimatedCosts;
    /**
     * @return The total count of VMs in migration
     * 
     */
    private @Nullable Integer vmCount;

    private MigrationPlanMigrationPlanStat() {}
    /**
     * @return The time when the migration plan was updated. An RFC3339 formatted datetime string.
     * 
     */
    public Optional<String> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }
    /**
     * @return Cost estimation description
     * 
     */
    public List<MigrationPlanMigrationPlanStatTotalEstimatedCost> totalEstimatedCosts() {
        return this.totalEstimatedCosts == null ? List.of() : this.totalEstimatedCosts;
    }
    /**
     * @return The total count of VMs in migration
     * 
     */
    public Optional<Integer> vmCount() {
        return Optional.ofNullable(this.vmCount);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(MigrationPlanMigrationPlanStat defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String timeUpdated;
        private @Nullable List<MigrationPlanMigrationPlanStatTotalEstimatedCost> totalEstimatedCosts;
        private @Nullable Integer vmCount;
        public Builder() {}
        public Builder(MigrationPlanMigrationPlanStat defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.totalEstimatedCosts = defaults.totalEstimatedCosts;
    	      this.vmCount = defaults.vmCount;
        }

        @CustomType.Setter
        public Builder timeUpdated(@Nullable String timeUpdated) {
            this.timeUpdated = timeUpdated;
            return this;
        }
        @CustomType.Setter
        public Builder totalEstimatedCosts(@Nullable List<MigrationPlanMigrationPlanStatTotalEstimatedCost> totalEstimatedCosts) {
            this.totalEstimatedCosts = totalEstimatedCosts;
            return this;
        }
        public Builder totalEstimatedCosts(MigrationPlanMigrationPlanStatTotalEstimatedCost... totalEstimatedCosts) {
            return totalEstimatedCosts(List.of(totalEstimatedCosts));
        }
        @CustomType.Setter
        public Builder vmCount(@Nullable Integer vmCount) {
            this.vmCount = vmCount;
            return this;
        }
        public MigrationPlanMigrationPlanStat build() {
            final var o = new MigrationPlanMigrationPlanStat();
            o.timeUpdated = timeUpdated;
            o.totalEstimatedCosts = totalEstimatedCosts;
            o.vmCount = vmCount;
            return o;
        }
    }
}