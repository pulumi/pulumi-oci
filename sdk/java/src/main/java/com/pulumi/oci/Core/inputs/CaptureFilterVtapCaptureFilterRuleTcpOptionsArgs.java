// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Core.inputs.CaptureFilterVtapCaptureFilterRuleTcpOptionsDestinationPortRangeArgs;
import com.pulumi.oci.Core.inputs.CaptureFilterVtapCaptureFilterRuleTcpOptionsSourcePortRangeArgs;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class CaptureFilterVtapCaptureFilterRuleTcpOptionsArgs extends com.pulumi.resources.ResourceArgs {

    public static final CaptureFilterVtapCaptureFilterRuleTcpOptionsArgs Empty = new CaptureFilterVtapCaptureFilterRuleTcpOptionsArgs();

    /**
     * (Updatable)
     * 
     */
    @Import(name="destinationPortRange")
    private @Nullable Output<CaptureFilterVtapCaptureFilterRuleTcpOptionsDestinationPortRangeArgs> destinationPortRange;

    /**
     * @return (Updatable)
     * 
     */
    public Optional<Output<CaptureFilterVtapCaptureFilterRuleTcpOptionsDestinationPortRangeArgs>> destinationPortRange() {
        return Optional.ofNullable(this.destinationPortRange);
    }

    /**
     * (Updatable)
     * 
     */
    @Import(name="sourcePortRange")
    private @Nullable Output<CaptureFilterVtapCaptureFilterRuleTcpOptionsSourcePortRangeArgs> sourcePortRange;

    /**
     * @return (Updatable)
     * 
     */
    public Optional<Output<CaptureFilterVtapCaptureFilterRuleTcpOptionsSourcePortRangeArgs>> sourcePortRange() {
        return Optional.ofNullable(this.sourcePortRange);
    }

    private CaptureFilterVtapCaptureFilterRuleTcpOptionsArgs() {}

    private CaptureFilterVtapCaptureFilterRuleTcpOptionsArgs(CaptureFilterVtapCaptureFilterRuleTcpOptionsArgs $) {
        this.destinationPortRange = $.destinationPortRange;
        this.sourcePortRange = $.sourcePortRange;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(CaptureFilterVtapCaptureFilterRuleTcpOptionsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private CaptureFilterVtapCaptureFilterRuleTcpOptionsArgs $;

        public Builder() {
            $ = new CaptureFilterVtapCaptureFilterRuleTcpOptionsArgs();
        }

        public Builder(CaptureFilterVtapCaptureFilterRuleTcpOptionsArgs defaults) {
            $ = new CaptureFilterVtapCaptureFilterRuleTcpOptionsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param destinationPortRange (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder destinationPortRange(@Nullable Output<CaptureFilterVtapCaptureFilterRuleTcpOptionsDestinationPortRangeArgs> destinationPortRange) {
            $.destinationPortRange = destinationPortRange;
            return this;
        }

        /**
         * @param destinationPortRange (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder destinationPortRange(CaptureFilterVtapCaptureFilterRuleTcpOptionsDestinationPortRangeArgs destinationPortRange) {
            return destinationPortRange(Output.of(destinationPortRange));
        }

        /**
         * @param sourcePortRange (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder sourcePortRange(@Nullable Output<CaptureFilterVtapCaptureFilterRuleTcpOptionsSourcePortRangeArgs> sourcePortRange) {
            $.sourcePortRange = sourcePortRange;
            return this;
        }

        /**
         * @param sourcePortRange (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder sourcePortRange(CaptureFilterVtapCaptureFilterRuleTcpOptionsSourcePortRangeArgs sourcePortRange) {
            return sourcePortRange(Output.of(sourcePortRange));
        }

        public CaptureFilterVtapCaptureFilterRuleTcpOptionsArgs build() {
            return $;
        }
    }

}
