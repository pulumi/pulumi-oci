// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.util.Objects;

@CustomType
public final class DefaultSecurityListEgressSecurityRuleTcpOptionsSourcePortRange {
    private Integer max;
    private Integer min;

    private DefaultSecurityListEgressSecurityRuleTcpOptionsSourcePortRange() {}
    public Integer max() {
        return this.max;
    }
    public Integer min() {
        return this.min;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DefaultSecurityListEgressSecurityRuleTcpOptionsSourcePortRange defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer max;
        private Integer min;
        public Builder() {}
        public Builder(DefaultSecurityListEgressSecurityRuleTcpOptionsSourcePortRange defaults) {
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
        public DefaultSecurityListEgressSecurityRuleTcpOptionsSourcePortRange build() {
            final var o = new DefaultSecurityListEgressSecurityRuleTcpOptionsSourcePortRange();
            o.max = max;
            o.min = min;
            return o;
        }
    }
}