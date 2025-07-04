// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ComputeHostConfigurationDataCheckDetailArgs extends com.pulumi.resources.ResourceArgs {

    public static final ComputeHostConfigurationDataCheckDetailArgs Empty = new ComputeHostConfigurationDataCheckDetailArgs();

    /**
     * Configuration state of the Compute Bare Metal Host.
     * 
     */
    @Import(name="configurationState")
    private @Nullable Output<String> configurationState;

    /**
     * @return Configuration state of the Compute Bare Metal Host.
     * 
     */
    public Optional<Output<String>> configurationState() {
        return Optional.ofNullable(this.configurationState);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the Customer-unique firmware bundle associated with the Host Configuration.
     * 
     */
    @Import(name="firmwareBundleId")
    private @Nullable Output<String> firmwareBundleId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the Customer-unique firmware bundle associated with the Host Configuration.
     * 
     */
    public Optional<Output<String>> firmwareBundleId() {
        return Optional.ofNullable(this.firmwareBundleId);
    }

    /**
     * Preferred recycle level for hosts associated with the reservation config.
     * * `SKIP_RECYCLE` - Skips host wipe.
     * * `FULL_RECYCLE` - Does not skip host wipe. This is the default behavior.
     * 
     */
    @Import(name="recycleLevel")
    private @Nullable Output<String> recycleLevel;

    /**
     * @return Preferred recycle level for hosts associated with the reservation config.
     * * `SKIP_RECYCLE` - Skips host wipe.
     * * `FULL_RECYCLE` - Does not skip host wipe. This is the default behavior.
     * 
     */
    public Optional<Output<String>> recycleLevel() {
        return Optional.ofNullable(this.recycleLevel);
    }

    /**
     * The type of configuration
     * 
     */
    @Import(name="type")
    private @Nullable Output<String> type;

    /**
     * @return The type of configuration
     * 
     */
    public Optional<Output<String>> type() {
        return Optional.ofNullable(this.type);
    }

    private ComputeHostConfigurationDataCheckDetailArgs() {}

    private ComputeHostConfigurationDataCheckDetailArgs(ComputeHostConfigurationDataCheckDetailArgs $) {
        this.configurationState = $.configurationState;
        this.firmwareBundleId = $.firmwareBundleId;
        this.recycleLevel = $.recycleLevel;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ComputeHostConfigurationDataCheckDetailArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ComputeHostConfigurationDataCheckDetailArgs $;

        public Builder() {
            $ = new ComputeHostConfigurationDataCheckDetailArgs();
        }

        public Builder(ComputeHostConfigurationDataCheckDetailArgs defaults) {
            $ = new ComputeHostConfigurationDataCheckDetailArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param configurationState Configuration state of the Compute Bare Metal Host.
         * 
         * @return builder
         * 
         */
        public Builder configurationState(@Nullable Output<String> configurationState) {
            $.configurationState = configurationState;
            return this;
        }

        /**
         * @param configurationState Configuration state of the Compute Bare Metal Host.
         * 
         * @return builder
         * 
         */
        public Builder configurationState(String configurationState) {
            return configurationState(Output.of(configurationState));
        }

        /**
         * @param firmwareBundleId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the Customer-unique firmware bundle associated with the Host Configuration.
         * 
         * @return builder
         * 
         */
        public Builder firmwareBundleId(@Nullable Output<String> firmwareBundleId) {
            $.firmwareBundleId = firmwareBundleId;
            return this;
        }

        /**
         * @param firmwareBundleId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the Customer-unique firmware bundle associated with the Host Configuration.
         * 
         * @return builder
         * 
         */
        public Builder firmwareBundleId(String firmwareBundleId) {
            return firmwareBundleId(Output.of(firmwareBundleId));
        }

        /**
         * @param recycleLevel Preferred recycle level for hosts associated with the reservation config.
         * * `SKIP_RECYCLE` - Skips host wipe.
         * * `FULL_RECYCLE` - Does not skip host wipe. This is the default behavior.
         * 
         * @return builder
         * 
         */
        public Builder recycleLevel(@Nullable Output<String> recycleLevel) {
            $.recycleLevel = recycleLevel;
            return this;
        }

        /**
         * @param recycleLevel Preferred recycle level for hosts associated with the reservation config.
         * * `SKIP_RECYCLE` - Skips host wipe.
         * * `FULL_RECYCLE` - Does not skip host wipe. This is the default behavior.
         * 
         * @return builder
         * 
         */
        public Builder recycleLevel(String recycleLevel) {
            return recycleLevel(Output.of(recycleLevel));
        }

        /**
         * @param type The type of configuration
         * 
         * @return builder
         * 
         */
        public Builder type(@Nullable Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type The type of configuration
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        public ComputeHostConfigurationDataCheckDetailArgs build() {
            return $;
        }
    }

}
