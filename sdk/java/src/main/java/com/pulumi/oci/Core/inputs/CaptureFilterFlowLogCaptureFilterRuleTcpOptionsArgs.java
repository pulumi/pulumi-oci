// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Core.inputs.CaptureFilterFlowLogCaptureFilterRuleTcpOptionsDestinationPortRangeArgs;
import com.pulumi.oci.Core.inputs.CaptureFilterFlowLogCaptureFilterRuleTcpOptionsSourcePortRangeArgs;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class CaptureFilterFlowLogCaptureFilterRuleTcpOptionsArgs extends com.pulumi.resources.ResourceArgs {

    public static final CaptureFilterFlowLogCaptureFilterRuleTcpOptionsArgs Empty = new CaptureFilterFlowLogCaptureFilterRuleTcpOptionsArgs();

    /**
     * (Updatable)
     * 
     */
    @Import(name="destinationPortRange")
    private @Nullable Output<CaptureFilterFlowLogCaptureFilterRuleTcpOptionsDestinationPortRangeArgs> destinationPortRange;

    /**
     * @return (Updatable)
     * 
     */
    public Optional<Output<CaptureFilterFlowLogCaptureFilterRuleTcpOptionsDestinationPortRangeArgs>> destinationPortRange() {
        return Optional.ofNullable(this.destinationPortRange);
    }

    /**
     * (Updatable)
     * 
     */
    @Import(name="sourcePortRange")
    private @Nullable Output<CaptureFilterFlowLogCaptureFilterRuleTcpOptionsSourcePortRangeArgs> sourcePortRange;

    /**
     * @return (Updatable)
     * 
     */
    public Optional<Output<CaptureFilterFlowLogCaptureFilterRuleTcpOptionsSourcePortRangeArgs>> sourcePortRange() {
        return Optional.ofNullable(this.sourcePortRange);
    }

    private CaptureFilterFlowLogCaptureFilterRuleTcpOptionsArgs() {}

    private CaptureFilterFlowLogCaptureFilterRuleTcpOptionsArgs(CaptureFilterFlowLogCaptureFilterRuleTcpOptionsArgs $) {
        this.destinationPortRange = $.destinationPortRange;
        this.sourcePortRange = $.sourcePortRange;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(CaptureFilterFlowLogCaptureFilterRuleTcpOptionsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private CaptureFilterFlowLogCaptureFilterRuleTcpOptionsArgs $;

        public Builder() {
            $ = new CaptureFilterFlowLogCaptureFilterRuleTcpOptionsArgs();
        }

        public Builder(CaptureFilterFlowLogCaptureFilterRuleTcpOptionsArgs defaults) {
            $ = new CaptureFilterFlowLogCaptureFilterRuleTcpOptionsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param destinationPortRange (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder destinationPortRange(@Nullable Output<CaptureFilterFlowLogCaptureFilterRuleTcpOptionsDestinationPortRangeArgs> destinationPortRange) {
            $.destinationPortRange = destinationPortRange;
            return this;
        }

        /**
         * @param destinationPortRange (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder destinationPortRange(CaptureFilterFlowLogCaptureFilterRuleTcpOptionsDestinationPortRangeArgs destinationPortRange) {
            return destinationPortRange(Output.of(destinationPortRange));
        }

        /**
         * @param sourcePortRange (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder sourcePortRange(@Nullable Output<CaptureFilterFlowLogCaptureFilterRuleTcpOptionsSourcePortRangeArgs> sourcePortRange) {
            $.sourcePortRange = sourcePortRange;
            return this;
        }

        /**
         * @param sourcePortRange (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder sourcePortRange(CaptureFilterFlowLogCaptureFilterRuleTcpOptionsSourcePortRangeArgs sourcePortRange) {
            return sourcePortRange(Output.of(sourcePortRange));
        }

        public CaptureFilterFlowLogCaptureFilterRuleTcpOptionsArgs build() {
            return $;
        }
    }

}