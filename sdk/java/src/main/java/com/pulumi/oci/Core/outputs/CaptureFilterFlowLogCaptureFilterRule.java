// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.CaptureFilterFlowLogCaptureFilterRuleIcmpOptions;
import com.pulumi.oci.Core.outputs.CaptureFilterFlowLogCaptureFilterRuleTcpOptions;
import com.pulumi.oci.Core.outputs.CaptureFilterFlowLogCaptureFilterRuleUdpOptions;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class CaptureFilterFlowLogCaptureFilterRule {
    /**
     * @return (Updatable) Traffic sent to this CIDR block through the VTAP source will be mirrored to the VTAP target.
     * 
     */
    private @Nullable String destinationCidr;
    /**
     * @return (Updatable) Type or types of flow logs to store. `ALL` includes records for both accepted traffic and rejected traffic.
     * 
     */
    private @Nullable String flowLogType;
    /**
     * @return (Updatable) Optional and valid only for ICMP and ICMPv6. Use to specify a particular ICMP type and code as defined in:
     * * [ICMP Parameters](http://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml)
     * * [ICMPv6 Parameters](https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml)
     * 
     * If you specify ICMP or ICMPv6 as the protocol but omit this object, then all ICMP types and codes are allowed. If you do provide this object, the type is required and the code is optional. To enable MTU negotiation for ingress internet traffic via IPv4, make sure to allow type 3 (&#34;Destination Unreachable&#34;) code 4 (&#34;Fragmentation Needed and Don&#39;t Fragment was Set&#34;). If you need to specify multiple codes for a single type, create a separate security list rule for each.
     * 
     */
    private @Nullable CaptureFilterFlowLogCaptureFilterRuleIcmpOptions icmpOptions;
    /**
     * @return (Updatable) Indicates whether a flow log capture filter rule is enabled.
     * 
     */
    private @Nullable Boolean isEnabled;
    /**
     * @return (Updatable) A lower number indicates a higher priority, range 0-9. Each rule must have a distinct priority.
     * 
     */
    private @Nullable Integer priority;
    /**
     * @return (Updatable) The transport protocol used in the filter. If do not choose a protocol, all protocols will be used in the filter. Supported options are:
     * * 1 = ICMP
     * * 6 = TCP
     * * 17 = UDP
     * 
     */
    private @Nullable String protocol;
    /**
     * @return (Updatable) Include or exclude packets meeting this definition from mirrored traffic.
     * 
     */
    private @Nullable String ruleAction;
    /**
     * @return (Updatable) Sampling interval as 1 of X, where X is an integer not greater than 100000.
     * 
     */
    private @Nullable Integer samplingRate;
    /**
     * @return (Updatable) Traffic from this CIDR block to the VTAP source will be mirrored to the VTAP target.
     * 
     */
    private @Nullable String sourceCidr;
    /**
     * @return (Updatable) Optional and valid only for TCP. Use to specify particular destination ports for TCP rules. If you specify TCP as the protocol but omit this object, then all destination ports are allowed.
     * 
     */
    private @Nullable CaptureFilterFlowLogCaptureFilterRuleTcpOptions tcpOptions;
    /**
     * @return (Updatable) Optional and valid only for UDP. Use to specify particular destination ports for UDP rules. If you specify UDP as the protocol but omit this object, then all destination ports are allowed.
     * 
     */
    private @Nullable CaptureFilterFlowLogCaptureFilterRuleUdpOptions udpOptions;

    private CaptureFilterFlowLogCaptureFilterRule() {}
    /**
     * @return (Updatable) Traffic sent to this CIDR block through the VTAP source will be mirrored to the VTAP target.
     * 
     */
    public Optional<String> destinationCidr() {
        return Optional.ofNullable(this.destinationCidr);
    }
    /**
     * @return (Updatable) Type or types of flow logs to store. `ALL` includes records for both accepted traffic and rejected traffic.
     * 
     */
    public Optional<String> flowLogType() {
        return Optional.ofNullable(this.flowLogType);
    }
    /**
     * @return (Updatable) Optional and valid only for ICMP and ICMPv6. Use to specify a particular ICMP type and code as defined in:
     * * [ICMP Parameters](http://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml)
     * * [ICMPv6 Parameters](https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml)
     * 
     * If you specify ICMP or ICMPv6 as the protocol but omit this object, then all ICMP types and codes are allowed. If you do provide this object, the type is required and the code is optional. To enable MTU negotiation for ingress internet traffic via IPv4, make sure to allow type 3 (&#34;Destination Unreachable&#34;) code 4 (&#34;Fragmentation Needed and Don&#39;t Fragment was Set&#34;). If you need to specify multiple codes for a single type, create a separate security list rule for each.
     * 
     */
    public Optional<CaptureFilterFlowLogCaptureFilterRuleIcmpOptions> icmpOptions() {
        return Optional.ofNullable(this.icmpOptions);
    }
    /**
     * @return (Updatable) Indicates whether a flow log capture filter rule is enabled.
     * 
     */
    public Optional<Boolean> isEnabled() {
        return Optional.ofNullable(this.isEnabled);
    }
    /**
     * @return (Updatable) A lower number indicates a higher priority, range 0-9. Each rule must have a distinct priority.
     * 
     */
    public Optional<Integer> priority() {
        return Optional.ofNullable(this.priority);
    }
    /**
     * @return (Updatable) The transport protocol used in the filter. If do not choose a protocol, all protocols will be used in the filter. Supported options are:
     * * 1 = ICMP
     * * 6 = TCP
     * * 17 = UDP
     * 
     */
    public Optional<String> protocol() {
        return Optional.ofNullable(this.protocol);
    }
    /**
     * @return (Updatable) Include or exclude packets meeting this definition from mirrored traffic.
     * 
     */
    public Optional<String> ruleAction() {
        return Optional.ofNullable(this.ruleAction);
    }
    /**
     * @return (Updatable) Sampling interval as 1 of X, where X is an integer not greater than 100000.
     * 
     */
    public Optional<Integer> samplingRate() {
        return Optional.ofNullable(this.samplingRate);
    }
    /**
     * @return (Updatable) Traffic from this CIDR block to the VTAP source will be mirrored to the VTAP target.
     * 
     */
    public Optional<String> sourceCidr() {
        return Optional.ofNullable(this.sourceCidr);
    }
    /**
     * @return (Updatable) Optional and valid only for TCP. Use to specify particular destination ports for TCP rules. If you specify TCP as the protocol but omit this object, then all destination ports are allowed.
     * 
     */
    public Optional<CaptureFilterFlowLogCaptureFilterRuleTcpOptions> tcpOptions() {
        return Optional.ofNullable(this.tcpOptions);
    }
    /**
     * @return (Updatable) Optional and valid only for UDP. Use to specify particular destination ports for UDP rules. If you specify UDP as the protocol but omit this object, then all destination ports are allowed.
     * 
     */
    public Optional<CaptureFilterFlowLogCaptureFilterRuleUdpOptions> udpOptions() {
        return Optional.ofNullable(this.udpOptions);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(CaptureFilterFlowLogCaptureFilterRule defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String destinationCidr;
        private @Nullable String flowLogType;
        private @Nullable CaptureFilterFlowLogCaptureFilterRuleIcmpOptions icmpOptions;
        private @Nullable Boolean isEnabled;
        private @Nullable Integer priority;
        private @Nullable String protocol;
        private @Nullable String ruleAction;
        private @Nullable Integer samplingRate;
        private @Nullable String sourceCidr;
        private @Nullable CaptureFilterFlowLogCaptureFilterRuleTcpOptions tcpOptions;
        private @Nullable CaptureFilterFlowLogCaptureFilterRuleUdpOptions udpOptions;
        public Builder() {}
        public Builder(CaptureFilterFlowLogCaptureFilterRule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.destinationCidr = defaults.destinationCidr;
    	      this.flowLogType = defaults.flowLogType;
    	      this.icmpOptions = defaults.icmpOptions;
    	      this.isEnabled = defaults.isEnabled;
    	      this.priority = defaults.priority;
    	      this.protocol = defaults.protocol;
    	      this.ruleAction = defaults.ruleAction;
    	      this.samplingRate = defaults.samplingRate;
    	      this.sourceCidr = defaults.sourceCidr;
    	      this.tcpOptions = defaults.tcpOptions;
    	      this.udpOptions = defaults.udpOptions;
        }

        @CustomType.Setter
        public Builder destinationCidr(@Nullable String destinationCidr) {
            this.destinationCidr = destinationCidr;
            return this;
        }
        @CustomType.Setter
        public Builder flowLogType(@Nullable String flowLogType) {
            this.flowLogType = flowLogType;
            return this;
        }
        @CustomType.Setter
        public Builder icmpOptions(@Nullable CaptureFilterFlowLogCaptureFilterRuleIcmpOptions icmpOptions) {
            this.icmpOptions = icmpOptions;
            return this;
        }
        @CustomType.Setter
        public Builder isEnabled(@Nullable Boolean isEnabled) {
            this.isEnabled = isEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder priority(@Nullable Integer priority) {
            this.priority = priority;
            return this;
        }
        @CustomType.Setter
        public Builder protocol(@Nullable String protocol) {
            this.protocol = protocol;
            return this;
        }
        @CustomType.Setter
        public Builder ruleAction(@Nullable String ruleAction) {
            this.ruleAction = ruleAction;
            return this;
        }
        @CustomType.Setter
        public Builder samplingRate(@Nullable Integer samplingRate) {
            this.samplingRate = samplingRate;
            return this;
        }
        @CustomType.Setter
        public Builder sourceCidr(@Nullable String sourceCidr) {
            this.sourceCidr = sourceCidr;
            return this;
        }
        @CustomType.Setter
        public Builder tcpOptions(@Nullable CaptureFilterFlowLogCaptureFilterRuleTcpOptions tcpOptions) {
            this.tcpOptions = tcpOptions;
            return this;
        }
        @CustomType.Setter
        public Builder udpOptions(@Nullable CaptureFilterFlowLogCaptureFilterRuleUdpOptions udpOptions) {
            this.udpOptions = udpOptions;
            return this;
        }
        public CaptureFilterFlowLogCaptureFilterRule build() {
            final var o = new CaptureFilterFlowLogCaptureFilterRule();
            o.destinationCidr = destinationCidr;
            o.flowLogType = flowLogType;
            o.icmpOptions = icmpOptions;
            o.isEnabled = isEnabled;
            o.priority = priority;
            o.protocol = protocol;
            o.ruleAction = ruleAction;
            o.samplingRate = samplingRate;
            o.sourceCidr = sourceCidr;
            o.tcpOptions = tcpOptions;
            o.udpOptions = udpOptions;
            return o;
        }
    }
}