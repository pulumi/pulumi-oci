// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.util.Objects;

@CustomType
public final class CaptureFilterVtapCaptureFilterRuleUdpOptionsDestinationPortRange {
    /**
     * @return (Updatable) The maximum port number, which must not be less than the minimum port number. To specify a single port number, set both the min and max to the same value.
     * 
     */
    private Integer max;
    /**
     * @return (Updatable) The minimum port number, which must not be greater than the maximum port number.
     * 
     */
    private Integer min;

    private CaptureFilterVtapCaptureFilterRuleUdpOptionsDestinationPortRange() {}
    /**
     * @return (Updatable) The maximum port number, which must not be less than the minimum port number. To specify a single port number, set both the min and max to the same value.
     * 
     */
    public Integer max() {
        return this.max;
    }
    /**
     * @return (Updatable) The minimum port number, which must not be greater than the maximum port number.
     * 
     */
    public Integer min() {
        return this.min;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(CaptureFilterVtapCaptureFilterRuleUdpOptionsDestinationPortRange defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer max;
        private Integer min;
        public Builder() {}
        public Builder(CaptureFilterVtapCaptureFilterRuleUdpOptionsDestinationPortRange defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.max = defaults.max;
    	      this.min = defaults.min;
        }

        @CustomType.Setter
        public Builder max(Integer max) {
            this.max = Objects.requireNonNull(max);
            return this;
        }
        @CustomType.Setter
        public Builder min(Integer min) {
            this.min = Objects.requireNonNull(min);
            return this;
        }
        public CaptureFilterVtapCaptureFilterRuleUdpOptionsDestinationPortRange build() {
            final var o = new CaptureFilterVtapCaptureFilterRuleUdpOptionsDestinationPortRange();
            o.max = max;
            o.min = min;
            return o;
        }
    }
}