// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GoldenGate.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.Integer;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DeploymentMaintenanceConfigurationArgs extends com.pulumi.resources.ResourceArgs {

    public static final DeploymentMaintenanceConfigurationArgs Empty = new DeploymentMaintenanceConfigurationArgs();

    /**
     * (Updatable) Defines auto upgrade period for bundle releases. Manually configured period cannot be longer than service defined period for bundle releases. This period must be shorter or equal to major release upgrade period. Not passing this field during create will equate to using the service default.
     * 
     */
    @Import(name="bundleReleaseUpgradePeriodInDays")
    private @Nullable Output<Integer> bundleReleaseUpgradePeriodInDays;

    /**
     * @return (Updatable) Defines auto upgrade period for bundle releases. Manually configured period cannot be longer than service defined period for bundle releases. This period must be shorter or equal to major release upgrade period. Not passing this field during create will equate to using the service default.
     * 
     */
    public Optional<Output<Integer>> bundleReleaseUpgradePeriodInDays() {
        return Optional.ofNullable(this.bundleReleaseUpgradePeriodInDays);
    }

    /**
     * (Updatable) Defines auto upgrade period for interim releases. This period must be shorter or equal to bundle release upgrade period.
     * 
     */
    @Import(name="interimReleaseUpgradePeriodInDays")
    private @Nullable Output<Integer> interimReleaseUpgradePeriodInDays;

    /**
     * @return (Updatable) Defines auto upgrade period for interim releases. This period must be shorter or equal to bundle release upgrade period.
     * 
     */
    public Optional<Output<Integer>> interimReleaseUpgradePeriodInDays() {
        return Optional.ofNullable(this.interimReleaseUpgradePeriodInDays);
    }

    /**
     * (Updatable) By default auto upgrade for interim releases are not enabled. If auto-upgrade is enabled for interim release,  you have to specify interimReleaseUpgradePeriodInDays too.
     * 
     */
    @Import(name="isInterimReleaseAutoUpgradeEnabled")
    private @Nullable Output<Boolean> isInterimReleaseAutoUpgradeEnabled;

    /**
     * @return (Updatable) By default auto upgrade for interim releases are not enabled. If auto-upgrade is enabled for interim release,  you have to specify interimReleaseUpgradePeriodInDays too.
     * 
     */
    public Optional<Output<Boolean>> isInterimReleaseAutoUpgradeEnabled() {
        return Optional.ofNullable(this.isInterimReleaseAutoUpgradeEnabled);
    }

    /**
     * (Updatable) Defines auto upgrade period for major releases. Manually configured period cannot be longer than service defined period for major releases. Not passing this field during create will equate to using the service default.
     * 
     */
    @Import(name="majorReleaseUpgradePeriodInDays")
    private @Nullable Output<Integer> majorReleaseUpgradePeriodInDays;

    /**
     * @return (Updatable) Defines auto upgrade period for major releases. Manually configured period cannot be longer than service defined period for major releases. Not passing this field during create will equate to using the service default.
     * 
     */
    public Optional<Output<Integer>> majorReleaseUpgradePeriodInDays() {
        return Optional.ofNullable(this.majorReleaseUpgradePeriodInDays);
    }

    /**
     * (Updatable) Defines auto upgrade period for releases with security fix. Manually configured period cannot be longer than service defined period for security releases. Not passing this field during create will equate to using the service default.
     * 
     */
    @Import(name="securityPatchUpgradePeriodInDays")
    private @Nullable Output<Integer> securityPatchUpgradePeriodInDays;

    /**
     * @return (Updatable) Defines auto upgrade period for releases with security fix. Manually configured period cannot be longer than service defined period for security releases. Not passing this field during create will equate to using the service default.
     * 
     */
    public Optional<Output<Integer>> securityPatchUpgradePeriodInDays() {
        return Optional.ofNullable(this.securityPatchUpgradePeriodInDays);
    }

    private DeploymentMaintenanceConfigurationArgs() {}

    private DeploymentMaintenanceConfigurationArgs(DeploymentMaintenanceConfigurationArgs $) {
        this.bundleReleaseUpgradePeriodInDays = $.bundleReleaseUpgradePeriodInDays;
        this.interimReleaseUpgradePeriodInDays = $.interimReleaseUpgradePeriodInDays;
        this.isInterimReleaseAutoUpgradeEnabled = $.isInterimReleaseAutoUpgradeEnabled;
        this.majorReleaseUpgradePeriodInDays = $.majorReleaseUpgradePeriodInDays;
        this.securityPatchUpgradePeriodInDays = $.securityPatchUpgradePeriodInDays;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DeploymentMaintenanceConfigurationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DeploymentMaintenanceConfigurationArgs $;

        public Builder() {
            $ = new DeploymentMaintenanceConfigurationArgs();
        }

        public Builder(DeploymentMaintenanceConfigurationArgs defaults) {
            $ = new DeploymentMaintenanceConfigurationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param bundleReleaseUpgradePeriodInDays (Updatable) Defines auto upgrade period for bundle releases. Manually configured period cannot be longer than service defined period for bundle releases. This period must be shorter or equal to major release upgrade period. Not passing this field during create will equate to using the service default.
         * 
         * @return builder
         * 
         */
        public Builder bundleReleaseUpgradePeriodInDays(@Nullable Output<Integer> bundleReleaseUpgradePeriodInDays) {
            $.bundleReleaseUpgradePeriodInDays = bundleReleaseUpgradePeriodInDays;
            return this;
        }

        /**
         * @param bundleReleaseUpgradePeriodInDays (Updatable) Defines auto upgrade period for bundle releases. Manually configured period cannot be longer than service defined period for bundle releases. This period must be shorter or equal to major release upgrade period. Not passing this field during create will equate to using the service default.
         * 
         * @return builder
         * 
         */
        public Builder bundleReleaseUpgradePeriodInDays(Integer bundleReleaseUpgradePeriodInDays) {
            return bundleReleaseUpgradePeriodInDays(Output.of(bundleReleaseUpgradePeriodInDays));
        }

        /**
         * @param interimReleaseUpgradePeriodInDays (Updatable) Defines auto upgrade period for interim releases. This period must be shorter or equal to bundle release upgrade period.
         * 
         * @return builder
         * 
         */
        public Builder interimReleaseUpgradePeriodInDays(@Nullable Output<Integer> interimReleaseUpgradePeriodInDays) {
            $.interimReleaseUpgradePeriodInDays = interimReleaseUpgradePeriodInDays;
            return this;
        }

        /**
         * @param interimReleaseUpgradePeriodInDays (Updatable) Defines auto upgrade period for interim releases. This period must be shorter or equal to bundle release upgrade period.
         * 
         * @return builder
         * 
         */
        public Builder interimReleaseUpgradePeriodInDays(Integer interimReleaseUpgradePeriodInDays) {
            return interimReleaseUpgradePeriodInDays(Output.of(interimReleaseUpgradePeriodInDays));
        }

        /**
         * @param isInterimReleaseAutoUpgradeEnabled (Updatable) By default auto upgrade for interim releases are not enabled. If auto-upgrade is enabled for interim release,  you have to specify interimReleaseUpgradePeriodInDays too.
         * 
         * @return builder
         * 
         */
        public Builder isInterimReleaseAutoUpgradeEnabled(@Nullable Output<Boolean> isInterimReleaseAutoUpgradeEnabled) {
            $.isInterimReleaseAutoUpgradeEnabled = isInterimReleaseAutoUpgradeEnabled;
            return this;
        }

        /**
         * @param isInterimReleaseAutoUpgradeEnabled (Updatable) By default auto upgrade for interim releases are not enabled. If auto-upgrade is enabled for interim release,  you have to specify interimReleaseUpgradePeriodInDays too.
         * 
         * @return builder
         * 
         */
        public Builder isInterimReleaseAutoUpgradeEnabled(Boolean isInterimReleaseAutoUpgradeEnabled) {
            return isInterimReleaseAutoUpgradeEnabled(Output.of(isInterimReleaseAutoUpgradeEnabled));
        }

        /**
         * @param majorReleaseUpgradePeriodInDays (Updatable) Defines auto upgrade period for major releases. Manually configured period cannot be longer than service defined period for major releases. Not passing this field during create will equate to using the service default.
         * 
         * @return builder
         * 
         */
        public Builder majorReleaseUpgradePeriodInDays(@Nullable Output<Integer> majorReleaseUpgradePeriodInDays) {
            $.majorReleaseUpgradePeriodInDays = majorReleaseUpgradePeriodInDays;
            return this;
        }

        /**
         * @param majorReleaseUpgradePeriodInDays (Updatable) Defines auto upgrade period for major releases. Manually configured period cannot be longer than service defined period for major releases. Not passing this field during create will equate to using the service default.
         * 
         * @return builder
         * 
         */
        public Builder majorReleaseUpgradePeriodInDays(Integer majorReleaseUpgradePeriodInDays) {
            return majorReleaseUpgradePeriodInDays(Output.of(majorReleaseUpgradePeriodInDays));
        }

        /**
         * @param securityPatchUpgradePeriodInDays (Updatable) Defines auto upgrade period for releases with security fix. Manually configured period cannot be longer than service defined period for security releases. Not passing this field during create will equate to using the service default.
         * 
         * @return builder
         * 
         */
        public Builder securityPatchUpgradePeriodInDays(@Nullable Output<Integer> securityPatchUpgradePeriodInDays) {
            $.securityPatchUpgradePeriodInDays = securityPatchUpgradePeriodInDays;
            return this;
        }

        /**
         * @param securityPatchUpgradePeriodInDays (Updatable) Defines auto upgrade period for releases with security fix. Manually configured period cannot be longer than service defined period for security releases. Not passing this field during create will equate to using the service default.
         * 
         * @return builder
         * 
         */
        public Builder securityPatchUpgradePeriodInDays(Integer securityPatchUpgradePeriodInDays) {
            return securityPatchUpgradePeriodInDays(Output.of(securityPatchUpgradePeriodInDays));
        }

        public DeploymentMaintenanceConfigurationArgs build() {
            return $;
        }
    }

}
