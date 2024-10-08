// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FusionApps.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.FusionApps.inputs.FusionEnvironmentMaintenancePolicyQuarterlyUpgradeBeginTimeArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class FusionEnvironmentMaintenancePolicyArgs extends com.pulumi.resources.ResourceArgs {

    public static final FusionEnvironmentMaintenancePolicyArgs Empty = new FusionEnvironmentMaintenancePolicyArgs();

    /**
     * (Updatable) User choice to upgrade both test and prod pods at the same time. Overrides fusion environment families&#39;.
     * 
     */
    @Import(name="environmentMaintenanceOverride")
    private @Nullable Output<String> environmentMaintenanceOverride;

    /**
     * @return (Updatable) User choice to upgrade both test and prod pods at the same time. Overrides fusion environment families&#39;.
     * 
     */
    public Optional<Output<String>> environmentMaintenanceOverride() {
        return Optional.ofNullable(this.environmentMaintenanceOverride);
    }

    /**
     * (Updatable) When &#34;ENABLED&#34;, the Fusion environment is patched monthly. When &#34;DISABLED&#34;, the Fusion environment is not patched monthly. This setting overrides the environment family setting. When not set, the environment follows the environment family policy.
     * 
     */
    @Import(name="monthlyPatchingOverride")
    private @Nullable Output<String> monthlyPatchingOverride;

    /**
     * @return (Updatable) When &#34;ENABLED&#34;, the Fusion environment is patched monthly. When &#34;DISABLED&#34;, the Fusion environment is not patched monthly. This setting overrides the environment family setting. When not set, the environment follows the environment family policy.
     * 
     */
    public Optional<Output<String>> monthlyPatchingOverride() {
        return Optional.ofNullable(this.monthlyPatchingOverride);
    }

    /**
     * Determines the quarterly upgrade begin times (monthly maintenance group schedule ) of the Fusion environment.
     * 
     */
    @Import(name="quarterlyUpgradeBeginTimes")
    private @Nullable Output<List<FusionEnvironmentMaintenancePolicyQuarterlyUpgradeBeginTimeArgs>> quarterlyUpgradeBeginTimes;

    /**
     * @return Determines the quarterly upgrade begin times (monthly maintenance group schedule ) of the Fusion environment.
     * 
     */
    public Optional<Output<List<FusionEnvironmentMaintenancePolicyQuarterlyUpgradeBeginTimeArgs>>> quarterlyUpgradeBeginTimes() {
        return Optional.ofNullable(this.quarterlyUpgradeBeginTimes);
    }

    private FusionEnvironmentMaintenancePolicyArgs() {}

    private FusionEnvironmentMaintenancePolicyArgs(FusionEnvironmentMaintenancePolicyArgs $) {
        this.environmentMaintenanceOverride = $.environmentMaintenanceOverride;
        this.monthlyPatchingOverride = $.monthlyPatchingOverride;
        this.quarterlyUpgradeBeginTimes = $.quarterlyUpgradeBeginTimes;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(FusionEnvironmentMaintenancePolicyArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private FusionEnvironmentMaintenancePolicyArgs $;

        public Builder() {
            $ = new FusionEnvironmentMaintenancePolicyArgs();
        }

        public Builder(FusionEnvironmentMaintenancePolicyArgs defaults) {
            $ = new FusionEnvironmentMaintenancePolicyArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param environmentMaintenanceOverride (Updatable) User choice to upgrade both test and prod pods at the same time. Overrides fusion environment families&#39;.
         * 
         * @return builder
         * 
         */
        public Builder environmentMaintenanceOverride(@Nullable Output<String> environmentMaintenanceOverride) {
            $.environmentMaintenanceOverride = environmentMaintenanceOverride;
            return this;
        }

        /**
         * @param environmentMaintenanceOverride (Updatable) User choice to upgrade both test and prod pods at the same time. Overrides fusion environment families&#39;.
         * 
         * @return builder
         * 
         */
        public Builder environmentMaintenanceOverride(String environmentMaintenanceOverride) {
            return environmentMaintenanceOverride(Output.of(environmentMaintenanceOverride));
        }

        /**
         * @param monthlyPatchingOverride (Updatable) When &#34;ENABLED&#34;, the Fusion environment is patched monthly. When &#34;DISABLED&#34;, the Fusion environment is not patched monthly. This setting overrides the environment family setting. When not set, the environment follows the environment family policy.
         * 
         * @return builder
         * 
         */
        public Builder monthlyPatchingOverride(@Nullable Output<String> monthlyPatchingOverride) {
            $.monthlyPatchingOverride = monthlyPatchingOverride;
            return this;
        }

        /**
         * @param monthlyPatchingOverride (Updatable) When &#34;ENABLED&#34;, the Fusion environment is patched monthly. When &#34;DISABLED&#34;, the Fusion environment is not patched monthly. This setting overrides the environment family setting. When not set, the environment follows the environment family policy.
         * 
         * @return builder
         * 
         */
        public Builder monthlyPatchingOverride(String monthlyPatchingOverride) {
            return monthlyPatchingOverride(Output.of(monthlyPatchingOverride));
        }

        /**
         * @param quarterlyUpgradeBeginTimes Determines the quarterly upgrade begin times (monthly maintenance group schedule ) of the Fusion environment.
         * 
         * @return builder
         * 
         */
        public Builder quarterlyUpgradeBeginTimes(@Nullable Output<List<FusionEnvironmentMaintenancePolicyQuarterlyUpgradeBeginTimeArgs>> quarterlyUpgradeBeginTimes) {
            $.quarterlyUpgradeBeginTimes = quarterlyUpgradeBeginTimes;
            return this;
        }

        /**
         * @param quarterlyUpgradeBeginTimes Determines the quarterly upgrade begin times (monthly maintenance group schedule ) of the Fusion environment.
         * 
         * @return builder
         * 
         */
        public Builder quarterlyUpgradeBeginTimes(List<FusionEnvironmentMaintenancePolicyQuarterlyUpgradeBeginTimeArgs> quarterlyUpgradeBeginTimes) {
            return quarterlyUpgradeBeginTimes(Output.of(quarterlyUpgradeBeginTimes));
        }

        /**
         * @param quarterlyUpgradeBeginTimes Determines the quarterly upgrade begin times (monthly maintenance group schedule ) of the Fusion environment.
         * 
         * @return builder
         * 
         */
        public Builder quarterlyUpgradeBeginTimes(FusionEnvironmentMaintenancePolicyQuarterlyUpgradeBeginTimeArgs... quarterlyUpgradeBeginTimes) {
            return quarterlyUpgradeBeginTimes(List.of(quarterlyUpgradeBeginTimes));
        }

        public FusionEnvironmentMaintenancePolicyArgs build() {
            return $;
        }
    }

}
