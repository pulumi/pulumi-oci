// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.DefaultSecurityListIngressSecurityRuleTcpOptionsSourcePortRange;
import java.lang.Integer;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DefaultSecurityListIngressSecurityRuleTcpOptions {
    private @Nullable Integer max;
    private @Nullable Integer min;
    private @Nullable DefaultSecurityListIngressSecurityRuleTcpOptionsSourcePortRange sourcePortRange;

    private DefaultSecurityListIngressSecurityRuleTcpOptions() {}
    public Optional<Integer> max() {
        return Optional.ofNullable(this.max);
    }
    public Optional<Integer> min() {
        return Optional.ofNullable(this.min);
    }
    public Optional<DefaultSecurityListIngressSecurityRuleTcpOptionsSourcePortRange> sourcePortRange() {
        return Optional.ofNullable(this.sourcePortRange);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DefaultSecurityListIngressSecurityRuleTcpOptions defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Integer max;
        private @Nullable Integer min;
        private @Nullable DefaultSecurityListIngressSecurityRuleTcpOptionsSourcePortRange sourcePortRange;
        public Builder() {}
        public Builder(DefaultSecurityListIngressSecurityRuleTcpOptions defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.max = defaults.max;
    	      this.min = defaults.min;
    	      this.sourcePortRange = defaults.sourcePortRange;
        }

        @CustomType.Setter
        public Builder max(@Nullable Integer max) {

            this.max = max;
            return this;
        }
        @CustomType.Setter
        public Builder min(@Nullable Integer min) {

            this.min = min;
            return this;
        }
        @CustomType.Setter
        public Builder sourcePortRange(@Nullable DefaultSecurityListIngressSecurityRuleTcpOptionsSourcePortRange sourcePortRange) {

            this.sourcePortRange = sourcePortRange;
            return this;
        }
        public DefaultSecurityListIngressSecurityRuleTcpOptions build() {
            final var _resultValue = new DefaultSecurityListIngressSecurityRuleTcpOptions();
            _resultValue.max = max;
            _resultValue.min = min;
            _resultValue.sourcePortRange = sourcePortRange;
            return _resultValue;
        }
    }
}
