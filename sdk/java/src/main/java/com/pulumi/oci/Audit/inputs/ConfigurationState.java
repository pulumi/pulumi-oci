// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Audit.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ConfigurationState extends com.pulumi.resources.ResourceArgs {

    public static final ConfigurationState Empty = new ConfigurationState();

    /**
     * ID of the root compartment (tenancy)
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return ID of the root compartment (tenancy)
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * (Updatable) The retention period setting, specified in days. The minimum is 90, the maximum 365.  Example: `90`
     * 
     */
    @Import(name="retentionPeriodDays")
    private @Nullable Output<Integer> retentionPeriodDays;

    /**
     * @return (Updatable) The retention period setting, specified in days. The minimum is 90, the maximum 365.  Example: `90`
     * 
     */
    public Optional<Output<Integer>> retentionPeriodDays() {
        return Optional.ofNullable(this.retentionPeriodDays);
    }

    private ConfigurationState() {}

    private ConfigurationState(ConfigurationState $) {
        this.compartmentId = $.compartmentId;
        this.retentionPeriodDays = $.retentionPeriodDays;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ConfigurationState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ConfigurationState $;

        public Builder() {
            $ = new ConfigurationState();
        }

        public Builder(ConfigurationState defaults) {
            $ = new ConfigurationState(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId ID of the root compartment (tenancy)
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId ID of the root compartment (tenancy)
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param retentionPeriodDays (Updatable) The retention period setting, specified in days. The minimum is 90, the maximum 365.  Example: `90`
         * 
         * @return builder
         * 
         */
        public Builder retentionPeriodDays(@Nullable Output<Integer> retentionPeriodDays) {
            $.retentionPeriodDays = retentionPeriodDays;
            return this;
        }

        /**
         * @param retentionPeriodDays (Updatable) The retention period setting, specified in days. The minimum is 90, the maximum 365.  Example: `90`
         * 
         * @return builder
         * 
         */
        public Builder retentionPeriodDays(Integer retentionPeriodDays) {
            return retentionPeriodDays(Output.of(retentionPeriodDays));
        }

        public ConfigurationState build() {
            return $;
        }
    }

}