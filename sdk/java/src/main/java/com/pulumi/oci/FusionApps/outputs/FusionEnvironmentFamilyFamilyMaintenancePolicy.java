// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FusionApps.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class FusionEnvironmentFamilyFamilyMaintenancePolicy {
    /**
     * @return (Updatable) Option to upgrade both production and non-production environments at the same time. When set to PROD both types of environnments are upgraded on the production schedule. When set to NON_PROD both types of environments are upgraded on the non-production schedule.
     * 
     */
    private @Nullable String concurrentMaintenance;
    /**
     * @return (Updatable) When True, monthly patching is enabled for the environment family.
     * 
     */
    private @Nullable Boolean isMonthlyPatchingEnabled;
    /**
     * @return The quarterly maintenance month group schedule of the Fusion environment family.
     * 
     */
    private @Nullable String quarterlyUpgradeBeginTimes;

    private FusionEnvironmentFamilyFamilyMaintenancePolicy() {}
    /**
     * @return (Updatable) Option to upgrade both production and non-production environments at the same time. When set to PROD both types of environnments are upgraded on the production schedule. When set to NON_PROD both types of environments are upgraded on the non-production schedule.
     * 
     */
    public Optional<String> concurrentMaintenance() {
        return Optional.ofNullable(this.concurrentMaintenance);
    }
    /**
     * @return (Updatable) When True, monthly patching is enabled for the environment family.
     * 
     */
    public Optional<Boolean> isMonthlyPatchingEnabled() {
        return Optional.ofNullable(this.isMonthlyPatchingEnabled);
    }
    /**
     * @return The quarterly maintenance month group schedule of the Fusion environment family.
     * 
     */
    public Optional<String> quarterlyUpgradeBeginTimes() {
        return Optional.ofNullable(this.quarterlyUpgradeBeginTimes);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(FusionEnvironmentFamilyFamilyMaintenancePolicy defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String concurrentMaintenance;
        private @Nullable Boolean isMonthlyPatchingEnabled;
        private @Nullable String quarterlyUpgradeBeginTimes;
        public Builder() {}
        public Builder(FusionEnvironmentFamilyFamilyMaintenancePolicy defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.concurrentMaintenance = defaults.concurrentMaintenance;
    	      this.isMonthlyPatchingEnabled = defaults.isMonthlyPatchingEnabled;
    	      this.quarterlyUpgradeBeginTimes = defaults.quarterlyUpgradeBeginTimes;
        }

        @CustomType.Setter
        public Builder concurrentMaintenance(@Nullable String concurrentMaintenance) {

            this.concurrentMaintenance = concurrentMaintenance;
            return this;
        }
        @CustomType.Setter
        public Builder isMonthlyPatchingEnabled(@Nullable Boolean isMonthlyPatchingEnabled) {

            this.isMonthlyPatchingEnabled = isMonthlyPatchingEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder quarterlyUpgradeBeginTimes(@Nullable String quarterlyUpgradeBeginTimes) {

            this.quarterlyUpgradeBeginTimes = quarterlyUpgradeBeginTimes;
            return this;
        }
        public FusionEnvironmentFamilyFamilyMaintenancePolicy build() {
            final var _resultValue = new FusionEnvironmentFamilyFamilyMaintenancePolicy();
            _resultValue.concurrentMaintenance = concurrentMaintenance;
            _resultValue.isMonthlyPatchingEnabled = isMonthlyPatchingEnabled;
            _resultValue.quarterlyUpgradeBeginTimes = quarterlyUpgradeBeginTimes;
            return _resultValue;
        }
    }
}
