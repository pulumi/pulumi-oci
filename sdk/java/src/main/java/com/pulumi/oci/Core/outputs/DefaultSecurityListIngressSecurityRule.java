// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.DefaultSecurityListIngressSecurityRuleIcmpOptions;
import com.pulumi.oci.Core.outputs.DefaultSecurityListIngressSecurityRuleTcpOptions;
import com.pulumi.oci.Core.outputs.DefaultSecurityListIngressSecurityRuleUdpOptions;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DefaultSecurityListIngressSecurityRule {
    private @Nullable String description;
    private @Nullable DefaultSecurityListIngressSecurityRuleIcmpOptions icmpOptions;
    private String protocol;
    private String source;
    private @Nullable String sourceType;
    private @Nullable Boolean stateless;
    private @Nullable DefaultSecurityListIngressSecurityRuleTcpOptions tcpOptions;
    private @Nullable DefaultSecurityListIngressSecurityRuleUdpOptions udpOptions;

    private DefaultSecurityListIngressSecurityRule() {}
    public Optional<String> description() {
        return Optional.ofNullable(this.description);
    }
    public Optional<DefaultSecurityListIngressSecurityRuleIcmpOptions> icmpOptions() {
        return Optional.ofNullable(this.icmpOptions);
    }
    public String protocol() {
        return this.protocol;
    }
    public String source() {
        return this.source;
    }
    public Optional<String> sourceType() {
        return Optional.ofNullable(this.sourceType);
    }
    public Optional<Boolean> stateless() {
        return Optional.ofNullable(this.stateless);
    }
    public Optional<DefaultSecurityListIngressSecurityRuleTcpOptions> tcpOptions() {
        return Optional.ofNullable(this.tcpOptions);
    }
    public Optional<DefaultSecurityListIngressSecurityRuleUdpOptions> udpOptions() {
        return Optional.ofNullable(this.udpOptions);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DefaultSecurityListIngressSecurityRule defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String description;
        private @Nullable DefaultSecurityListIngressSecurityRuleIcmpOptions icmpOptions;
        private String protocol;
        private String source;
        private @Nullable String sourceType;
        private @Nullable Boolean stateless;
        private @Nullable DefaultSecurityListIngressSecurityRuleTcpOptions tcpOptions;
        private @Nullable DefaultSecurityListIngressSecurityRuleUdpOptions udpOptions;
        public Builder() {}
        public Builder(DefaultSecurityListIngressSecurityRule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.description = defaults.description;
    	      this.icmpOptions = defaults.icmpOptions;
    	      this.protocol = defaults.protocol;
    	      this.source = defaults.source;
    	      this.sourceType = defaults.sourceType;
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
        public Builder icmpOptions(@Nullable DefaultSecurityListIngressSecurityRuleIcmpOptions icmpOptions) {
            this.icmpOptions = icmpOptions;
            return this;
        }
        @CustomType.Setter
        public Builder protocol(String protocol) {
            this.protocol = Objects.requireNonNull(protocol);
            return this;
        }
        @CustomType.Setter
        public Builder source(String source) {
            this.source = Objects.requireNonNull(source);
            return this;
        }
        @CustomType.Setter
        public Builder sourceType(@Nullable String sourceType) {
            this.sourceType = sourceType;
            return this;
        }
        @CustomType.Setter
        public Builder stateless(@Nullable Boolean stateless) {
            this.stateless = stateless;
            return this;
        }
        @CustomType.Setter
        public Builder tcpOptions(@Nullable DefaultSecurityListIngressSecurityRuleTcpOptions tcpOptions) {
            this.tcpOptions = tcpOptions;
            return this;
        }
        @CustomType.Setter
        public Builder udpOptions(@Nullable DefaultSecurityListIngressSecurityRuleUdpOptions udpOptions) {
            this.udpOptions = udpOptions;
            return this;
        }
        public DefaultSecurityListIngressSecurityRule build() {
            final var o = new DefaultSecurityListIngressSecurityRule();
            o.description = description;
            o.icmpOptions = icmpOptions;
            o.protocol = protocol;
            o.source = source;
            o.sourceType = sourceType;
            o.stateless = stateless;
            o.tcpOptions = tcpOptions;
            o.udpOptions = udpOptions;
            return o;
        }
    }
}