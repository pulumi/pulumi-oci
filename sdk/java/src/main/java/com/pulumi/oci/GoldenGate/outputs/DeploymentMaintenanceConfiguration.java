// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GoldenGate.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.Integer;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DeploymentMaintenanceConfiguration {
    /**
     * @return (Updatable) Defines auto upgrade period for bundle releases. Manually configured period cannot be longer than service defined period for bundle releases. This period must be shorter or equal to major release upgrade period. Not passing this field during create will equate to using the service default.
     * 
     */
    private @Nullable Integer bundleReleaseUpgradePeriodInDays;
    /**
     * @return (Updatable) Defines auto upgrade period for interim releases. This period must be shorter or equal to bundle release upgrade period.
     * 
     */
    private @Nullable Integer interimReleaseUpgradePeriodInDays;
    /**
     * @return (Updatable) By default auto upgrade for interim releases are not enabled. If auto-upgrade is enabled for interim release,  you have to specify interimReleaseUpgradePeriodInDays too.
     * 
     */
    private @Nullable Boolean isInterimReleaseAutoUpgradeEnabled;
    /**
     * @return (Updatable) Defines auto upgrade period for major releases. Manually configured period cannot be longer than service defined period for major releases. Not passing this field during create will equate to using the service default.
     * 
     */
    private @Nullable Integer majorReleaseUpgradePeriodInDays;
    /**
     * @return (Updatable) Defines auto upgrade period for releases with security fix. Manually configured period cannot be longer than service defined period for security releases. Not passing this field during create will equate to using the service default.
     * 
     */
    private @Nullable Integer securityPatchUpgradePeriodInDays;

    private DeploymentMaintenanceConfiguration() {}
    /**
     * @return (Updatable) Defines auto upgrade period for bundle releases. Manually configured period cannot be longer than service defined period for bundle releases. This period must be shorter or equal to major release upgrade period. Not passing this field during create will equate to using the service default.
     * 
     */
    public Optional<Integer> bundleReleaseUpgradePeriodInDays() {
        return Optional.ofNullable(this.bundleReleaseUpgradePeriodInDays);
    }
    /**
     * @return (Updatable) Defines auto upgrade period for interim releases. This period must be shorter or equal to bundle release upgrade period.
     * 
     */
    public Optional<Integer> interimReleaseUpgradePeriodInDays() {
        return Optional.ofNullable(this.interimReleaseUpgradePeriodInDays);
    }
    /**
     * @return (Updatable) By default auto upgrade for interim releases are not enabled. If auto-upgrade is enabled for interim release,  you have to specify interimReleaseUpgradePeriodInDays too.
     * 
     */
    public Optional<Boolean> isInterimReleaseAutoUpgradeEnabled() {
        return Optional.ofNullable(this.isInterimReleaseAutoUpgradeEnabled);
    }
    /**
     * @return (Updatable) Defines auto upgrade period for major releases. Manually configured period cannot be longer than service defined period for major releases. Not passing this field during create will equate to using the service default.
     * 
     */
    public Optional<Integer> majorReleaseUpgradePeriodInDays() {
        return Optional.ofNullable(this.majorReleaseUpgradePeriodInDays);
    }
    /**
     * @return (Updatable) Defines auto upgrade period for releases with security fix. Manually configured period cannot be longer than service defined period for security releases. Not passing this field during create will equate to using the service default.
     * 
     */
    public Optional<Integer> securityPatchUpgradePeriodInDays() {
        return Optional.ofNullable(this.securityPatchUpgradePeriodInDays);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DeploymentMaintenanceConfiguration defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Integer bundleReleaseUpgradePeriodInDays;
        private @Nullable Integer interimReleaseUpgradePeriodInDays;
        private @Nullable Boolean isInterimReleaseAutoUpgradeEnabled;
        private @Nullable Integer majorReleaseUpgradePeriodInDays;
        private @Nullable Integer securityPatchUpgradePeriodInDays;
        public Builder() {}
        public Builder(DeploymentMaintenanceConfiguration defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.bundleReleaseUpgradePeriodInDays = defaults.bundleReleaseUpgradePeriodInDays;
    	      this.interimReleaseUpgradePeriodInDays = defaults.interimReleaseUpgradePeriodInDays;
    	      this.isInterimReleaseAutoUpgradeEnabled = defaults.isInterimReleaseAutoUpgradeEnabled;
    	      this.majorReleaseUpgradePeriodInDays = defaults.majorReleaseUpgradePeriodInDays;
    	      this.securityPatchUpgradePeriodInDays = defaults.securityPatchUpgradePeriodInDays;
        }

        @CustomType.Setter
        public Builder bundleReleaseUpgradePeriodInDays(@Nullable Integer bundleReleaseUpgradePeriodInDays) {
            this.bundleReleaseUpgradePeriodInDays = bundleReleaseUpgradePeriodInDays;
            return this;
        }
        @CustomType.Setter
        public Builder interimReleaseUpgradePeriodInDays(@Nullable Integer interimReleaseUpgradePeriodInDays) {
            this.interimReleaseUpgradePeriodInDays = interimReleaseUpgradePeriodInDays;
            return this;
        }
        @CustomType.Setter
        public Builder isInterimReleaseAutoUpgradeEnabled(@Nullable Boolean isInterimReleaseAutoUpgradeEnabled) {
            this.isInterimReleaseAutoUpgradeEnabled = isInterimReleaseAutoUpgradeEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder majorReleaseUpgradePeriodInDays(@Nullable Integer majorReleaseUpgradePeriodInDays) {
            this.majorReleaseUpgradePeriodInDays = majorReleaseUpgradePeriodInDays;
            return this;
        }
        @CustomType.Setter
        public Builder securityPatchUpgradePeriodInDays(@Nullable Integer securityPatchUpgradePeriodInDays) {
            this.securityPatchUpgradePeriodInDays = securityPatchUpgradePeriodInDays;
            return this;
        }
        public DeploymentMaintenanceConfiguration build() {
            final var o = new DeploymentMaintenanceConfiguration();
            o.bundleReleaseUpgradePeriodInDays = bundleReleaseUpgradePeriodInDays;
            o.interimReleaseUpgradePeriodInDays = interimReleaseUpgradePeriodInDays;
            o.isInterimReleaseAutoUpgradeEnabled = isInterimReleaseAutoUpgradeEnabled;
            o.majorReleaseUpgradePeriodInDays = majorReleaseUpgradePeriodInDays;
            o.securityPatchUpgradePeriodInDays = securityPatchUpgradePeriodInDays;
            return o;
        }
    }
}