// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ComputeHostRecycleDetailArgs extends com.pulumi.resources.ResourceArgs {

    public static final ComputeHostRecycleDetailArgs Empty = new ComputeHostRecycleDetailArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute host group this host was attached to at the time of recycle.
     * 
     */
    @Import(name="computeHostGroupId")
    private @Nullable Output<String> computeHostGroupId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute host group this host was attached to at the time of recycle.
     * 
     */
    public Optional<Output<String>> computeHostGroupId() {
        return Optional.ofNullable(this.computeHostGroupId);
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

    private ComputeHostRecycleDetailArgs() {}

    private ComputeHostRecycleDetailArgs(ComputeHostRecycleDetailArgs $) {
        this.computeHostGroupId = $.computeHostGroupId;
        this.recycleLevel = $.recycleLevel;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ComputeHostRecycleDetailArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ComputeHostRecycleDetailArgs $;

        public Builder() {
            $ = new ComputeHostRecycleDetailArgs();
        }

        public Builder(ComputeHostRecycleDetailArgs defaults) {
            $ = new ComputeHostRecycleDetailArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param computeHostGroupId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute host group this host was attached to at the time of recycle.
         * 
         * @return builder
         * 
         */
        public Builder computeHostGroupId(@Nullable Output<String> computeHostGroupId) {
            $.computeHostGroupId = computeHostGroupId;
            return this;
        }

        /**
         * @param computeHostGroupId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute host group this host was attached to at the time of recycle.
         * 
         * @return builder
         * 
         */
        public Builder computeHostGroupId(String computeHostGroupId) {
            return computeHostGroupId(Output.of(computeHostGroupId));
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

        public ComputeHostRecycleDetailArgs build() {
            return $;
        }
    }

}
