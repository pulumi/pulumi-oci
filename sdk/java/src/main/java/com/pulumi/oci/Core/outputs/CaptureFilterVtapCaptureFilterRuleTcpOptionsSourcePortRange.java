// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.util.Objects;

@CustomType
public final class CaptureFilterVtapCaptureFilterRuleTcpOptionsSourcePortRange {
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

    private CaptureFilterVtapCaptureFilterRuleTcpOptionsSourcePortRange() {}
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

    public static Builder builder(CaptureFilterVtapCaptureFilterRuleTcpOptionsSourcePortRange defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer max;
        private Integer min;
        public Builder() {}
        public Builder(CaptureFilterVtapCaptureFilterRuleTcpOptionsSourcePortRange defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.max = defaults.max;
    	      this.min = defaults.min;
        }

        @CustomType.Setter
        public Builder max(Integer max) {
            if (max == null) {
              throw new MissingRequiredPropertyException("CaptureFilterVtapCaptureFilterRuleTcpOptionsSourcePortRange", "max");
            }
            this.max = max;
            return this;
        }
        @CustomType.Setter
        public Builder min(Integer min) {
            if (min == null) {
              throw new MissingRequiredPropertyException("CaptureFilterVtapCaptureFilterRuleTcpOptionsSourcePortRange", "min");
            }
            this.min = min;
            return this;
        }
        public CaptureFilterVtapCaptureFilterRuleTcpOptionsSourcePortRange build() {
            final var _resultValue = new CaptureFilterVtapCaptureFilterRuleTcpOptionsSourcePortRange();
            _resultValue.max = max;
            _resultValue.min = min;
            return _resultValue;
        }
    }
}
