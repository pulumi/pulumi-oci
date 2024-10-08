// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FusionApps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.FusionApps.outputs.FusionEnvironmentMaintenancePolicyQuarterlyUpgradeBeginTime;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class FusionEnvironmentMaintenancePolicy {
    /**
     * @return (Updatable) User choice to upgrade both test and prod pods at the same time. Overrides fusion environment families&#39;.
     * 
     */
    private @Nullable String environmentMaintenanceOverride;
    /**
     * @return (Updatable) When &#34;ENABLED&#34;, the Fusion environment is patched monthly. When &#34;DISABLED&#34;, the Fusion environment is not patched monthly. This setting overrides the environment family setting. When not set, the environment follows the environment family policy.
     * 
     */
    private @Nullable String monthlyPatchingOverride;
    /**
     * @return Determines the quarterly upgrade begin times (monthly maintenance group schedule ) of the Fusion environment.
     * 
     */
    private @Nullable List<FusionEnvironmentMaintenancePolicyQuarterlyUpgradeBeginTime> quarterlyUpgradeBeginTimes;

    private FusionEnvironmentMaintenancePolicy() {}
    /**
     * @return (Updatable) User choice to upgrade both test and prod pods at the same time. Overrides fusion environment families&#39;.
     * 
     */
    public Optional<String> environmentMaintenanceOverride() {
        return Optional.ofNullable(this.environmentMaintenanceOverride);
    }
    /**
     * @return (Updatable) When &#34;ENABLED&#34;, the Fusion environment is patched monthly. When &#34;DISABLED&#34;, the Fusion environment is not patched monthly. This setting overrides the environment family setting. When not set, the environment follows the environment family policy.
     * 
     */
    public Optional<String> monthlyPatchingOverride() {
        return Optional.ofNullable(this.monthlyPatchingOverride);
    }
    /**
     * @return Determines the quarterly upgrade begin times (monthly maintenance group schedule ) of the Fusion environment.
     * 
     */
    public List<FusionEnvironmentMaintenancePolicyQuarterlyUpgradeBeginTime> quarterlyUpgradeBeginTimes() {
        return this.quarterlyUpgradeBeginTimes == null ? List.of() : this.quarterlyUpgradeBeginTimes;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(FusionEnvironmentMaintenancePolicy defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String environmentMaintenanceOverride;
        private @Nullable String monthlyPatchingOverride;
        private @Nullable List<FusionEnvironmentMaintenancePolicyQuarterlyUpgradeBeginTime> quarterlyUpgradeBeginTimes;
        public Builder() {}
        public Builder(FusionEnvironmentMaintenancePolicy defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.environmentMaintenanceOverride = defaults.environmentMaintenanceOverride;
    	      this.monthlyPatchingOverride = defaults.monthlyPatchingOverride;
    	      this.quarterlyUpgradeBeginTimes = defaults.quarterlyUpgradeBeginTimes;
        }

        @CustomType.Setter
        public Builder environmentMaintenanceOverride(@Nullable String environmentMaintenanceOverride) {

            this.environmentMaintenanceOverride = environmentMaintenanceOverride;
            return this;
        }
        @CustomType.Setter
        public Builder monthlyPatchingOverride(@Nullable String monthlyPatchingOverride) {

            this.monthlyPatchingOverride = monthlyPatchingOverride;
            return this;
        }
        @CustomType.Setter
        public Builder quarterlyUpgradeBeginTimes(@Nullable List<FusionEnvironmentMaintenancePolicyQuarterlyUpgradeBeginTime> quarterlyUpgradeBeginTimes) {

            this.quarterlyUpgradeBeginTimes = quarterlyUpgradeBeginTimes;
            return this;
        }
        public Builder quarterlyUpgradeBeginTimes(FusionEnvironmentMaintenancePolicyQuarterlyUpgradeBeginTime... quarterlyUpgradeBeginTimes) {
            return quarterlyUpgradeBeginTimes(List.of(quarterlyUpgradeBeginTimes));
        }
        public FusionEnvironmentMaintenancePolicy build() {
            final var _resultValue = new FusionEnvironmentMaintenancePolicy();
            _resultValue.environmentMaintenanceOverride = environmentMaintenanceOverride;
            _resultValue.monthlyPatchingOverride = monthlyPatchingOverride;
            _resultValue.quarterlyUpgradeBeginTimes = quarterlyUpgradeBeginTimes;
            return _resultValue;
        }
    }
}
