// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.DefaultSecurityListEgressSecurityRuleIcmpOptions;
import com.pulumi.oci.Core.outputs.DefaultSecurityListEgressSecurityRuleTcpOptions;
import com.pulumi.oci.Core.outputs.DefaultSecurityListEgressSecurityRuleUdpOptions;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DefaultSecurityListEgressSecurityRule {
    private @Nullable String description;
    private String destination;
    private @Nullable String destinationType;
    private @Nullable DefaultSecurityListEgressSecurityRuleIcmpOptions icmpOptions;
    private String protocol;
    private @Nullable Boolean stateless;
    private @Nullable DefaultSecurityListEgressSecurityRuleTcpOptions tcpOptions;
    private @Nullable DefaultSecurityListEgressSecurityRuleUdpOptions udpOptions;

    private DefaultSecurityListEgressSecurityRule() {}
    public Optional<String> description() {
        return Optional.ofNullable(this.description);
    }
    public String destination() {
        return this.destination;
    }
    public Optional<String> destinationType() {
        return Optional.ofNullable(this.destinationType);
    }
    public Optional<DefaultSecurityListEgressSecurityRuleIcmpOptions> icmpOptions() {
        return Optional.ofNullable(this.icmpOptions);
    }
    public String protocol() {
        return this.protocol;
    }
    public Optional<Boolean> stateless() {
        return Optional.ofNullable(this.stateless);
    }
    public Optional<DefaultSecurityListEgressSecurityRuleTcpOptions> tcpOptions() {
        return Optional.ofNullable(this.tcpOptions);
    }
    public Optional<DefaultSecurityListEgressSecurityRuleUdpOptions> udpOptions() {
        return Optional.ofNullable(this.udpOptions);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DefaultSecurityListEgressSecurityRule defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String description;
        private String destination;
        private @Nullable String destinationType;
        private @Nullable DefaultSecurityListEgressSecurityRuleIcmpOptions icmpOptions;
        private String protocol;
        private @Nullable Boolean stateless;
        private @Nullable DefaultSecurityListEgressSecurityRuleTcpOptions tcpOptions;
        private @Nullable DefaultSecurityListEgressSecurityRuleUdpOptions udpOptions;
        public Builder() {}
        public Builder(DefaultSecurityListEgressSecurityRule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.description = defaults.description;
    	      this.destination = defaults.destination;
    	      this.destinationType = defaults.destinationType;
    	      this.icmpOptions = defaults.icmpOptions;
    	      this.protocol = defaults.protocol;
    	      this.stateless = defaults.stateless;
    	      this.tcpOptions = defaults.tcpOptions;
    	      this.udpOptions = defaults.udpOptions;
        }

        @CustomType.Setter
        public Builder description(@Nullable String description) {
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder destination(String destination) {
            this.destination = Objects.requireNonNull(destination);
            return this;
        }
        @CustomType.Setter
        public Builder destinationType(@Nullable String destinationType) {
            this.destinationType = destinationType;
            return this;
        }
        @CustomType.Setter
        public Builder icmpOptions(@Nullable DefaultSecurityListEgressSecurityRuleIcmpOptions icmpOptions) {
            this.icmpOptions = icmpOptions;
            return this;
        }
        @CustomType.Setter
        public Builder protocol(String protocol) {
            this.protocol = Objects.requireNonNull(protocol);
            return this;
        }
        @CustomType.Setter
        public Builder stateless(@Nullable Boolean stateless) {
            this.stateless = stateless;
            return this;
        }
        @CustomType.Setter
        public Builder tcpOptions(@Nullable DefaultSecurityListEgressSecurityRuleTcpOptions tcpOptions) {
            this.tcpOptions = tcpOptions;
            return this;
        }
        @CustomType.Setter
        public Builder udpOptions(@Nullable DefaultSecurityListEgressSecurityRuleUdpOptions udpOptions) {
            this.udpOptions = udpOptions;
            return this;
        }
        public DefaultSecurityListEgressSecurityRule build() {
            final var o = new DefaultSecurityListEgressSecurityRule();
            o.description = description;
            o.destination = destination;
            o.destinationType = destinationType;
            o.icmpOptions = icmpOptions;
            o.protocol = protocol;
            o.stateless = stateless;
            o.tcpOptions = tcpOptions;
            o.udpOptions = udpOptions;
            return o;
        }
    }
}