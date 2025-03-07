// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.CaptureFilterFlowLogCaptureFilterRuleUdpOptionsDestinationPortRange;
import com.pulumi.oci.Core.outputs.CaptureFilterFlowLogCaptureFilterRuleUdpOptionsSourcePortRange;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class CaptureFilterFlowLogCaptureFilterRuleUdpOptions {
    /**
     * @return (Updatable)
     * 
     */
    private @Nullable CaptureFilterFlowLogCaptureFilterRuleUdpOptionsDestinationPortRange destinationPortRange;
    /**
     * @return (Updatable)
     * 
     */
    private @Nullable CaptureFilterFlowLogCaptureFilterRuleUdpOptionsSourcePortRange sourcePortRange;

    private CaptureFilterFlowLogCaptureFilterRuleUdpOptions() {}
    /**
     * @return (Updatable)
     * 
     */
    public Optional<CaptureFilterFlowLogCaptureFilterRuleUdpOptionsDestinationPortRange> destinationPortRange() {
        return Optional.ofNullable(this.destinationPortRange);
    }
    /**
     * @return (Updatable)
     * 
     */
    public Optional<CaptureFilterFlowLogCaptureFilterRuleUdpOptionsSourcePortRange> sourcePortRange() {
        return Optional.ofNullable(this.sourcePortRange);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(CaptureFilterFlowLogCaptureFilterRuleUdpOptions defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable CaptureFilterFlowLogCaptureFilterRuleUdpOptionsDestinationPortRange destinationPortRange;
        private @Nullable CaptureFilterFlowLogCaptureFilterRuleUdpOptionsSourcePortRange sourcePortRange;
        public Builder() {}
        public Builder(CaptureFilterFlowLogCaptureFilterRuleUdpOptions defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.destinationPortRange = defaults.destinationPortRange;
    	      this.sourcePortRange = defaults.sourcePortRange;
        }

        @CustomType.Setter
        public Builder destinationPortRange(@Nullable CaptureFilterFlowLogCaptureFilterRuleUdpOptionsDestinationPortRange destinationPortRange) {

            this.destinationPortRange = destinationPortRange;
            return this;
        }
        @CustomType.Setter
        public Builder sourcePortRange(@Nullable CaptureFilterFlowLogCaptureFilterRuleUdpOptionsSourcePortRange sourcePortRange) {

            this.sourcePortRange = sourcePortRange;
            return this;
        }
        public CaptureFilterFlowLogCaptureFilterRuleUdpOptions build() {
            final var _resultValue = new CaptureFilterFlowLogCaptureFilterRuleUdpOptions();
            _resultValue.destinationPortRange = destinationPortRange;
            _resultValue.sourcePortRange = sourcePortRange;
            return _resultValue;
        }
    }
}
