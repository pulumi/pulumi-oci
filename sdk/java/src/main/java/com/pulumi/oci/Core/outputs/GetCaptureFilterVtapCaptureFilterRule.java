// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetCaptureFilterVtapCaptureFilterRuleIcmpOption;
import com.pulumi.oci.Core.outputs.GetCaptureFilterVtapCaptureFilterRuleTcpOption;
import com.pulumi.oci.Core.outputs.GetCaptureFilterVtapCaptureFilterRuleUdpOption;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetCaptureFilterVtapCaptureFilterRule {
    /**
     * @return Traffic sent to this CIDR block through the VTAP source will be mirrored to the VTAP target.
     * 
     */
    private String destinationCidr;
    /**
     * @return Optional and valid only for ICMP and ICMPv6. Use to specify a particular ICMP type and code as defined in:
     * * [ICMP Parameters](http://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml)
     * * [ICMPv6 Parameters](https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml)
     * 
     */
    private List<GetCaptureFilterVtapCaptureFilterRuleIcmpOption> icmpOptions;
    /**
     * @return The transport protocol used in the filter. If do not choose a protocol, all protocols will be used in the filter. Supported options are:
     * * 1 = ICMP
     * * 6 = TCP
     * * 17 = UDP
     * 
     */
    private String protocol;
    /**
     * @return Include or exclude packets meeting this definition from mirrored traffic.
     * 
     */
    private String ruleAction;
    /**
     * @return Traffic from this CIDR block to the VTAP source will be mirrored to the VTAP target.
     * 
     */
    private String sourceCidr;
    /**
     * @return Optional and valid only for TCP. Use to specify particular destination ports for TCP rules. If you specify TCP as the protocol but omit this object, then all destination ports are allowed.
     * 
     */
    private List<GetCaptureFilterVtapCaptureFilterRuleTcpOption> tcpOptions;
    /**
     * @return The traffic direction the VTAP is configured to mirror.
     * 
     */
    private String trafficDirection;
    /**
     * @return Optional and valid only for UDP. Use to specify particular destination ports for UDP rules. If you specify UDP as the protocol but omit this object, then all destination ports are allowed.
     * 
     */
    private List<GetCaptureFilterVtapCaptureFilterRuleUdpOption> udpOptions;

    private GetCaptureFilterVtapCaptureFilterRule() {}
    /**
     * @return Traffic sent to this CIDR block through the VTAP source will be mirrored to the VTAP target.
     * 
     */
    public String destinationCidr() {
        return this.destinationCidr;
    }
    /**
     * @return Optional and valid only for ICMP and ICMPv6. Use to specify a particular ICMP type and code as defined in:
     * * [ICMP Parameters](http://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml)
     * * [ICMPv6 Parameters](https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml)
     * 
     */
    public List<GetCaptureFilterVtapCaptureFilterRuleIcmpOption> icmpOptions() {
        return this.icmpOptions;
    }
    /**
     * @return The transport protocol used in the filter. If do not choose a protocol, all protocols will be used in the filter. Supported options are:
     * * 1 = ICMP
     * * 6 = TCP
     * * 17 = UDP
     * 
     */
    public String protocol() {
        return this.protocol;
    }
    /**
     * @return Include or exclude packets meeting this definition from mirrored traffic.
     * 
     */
    public String ruleAction() {
        return this.ruleAction;
    }
    /**
     * @return Traffic from this CIDR block to the VTAP source will be mirrored to the VTAP target.
     * 
     */
    public String sourceCidr() {
        return this.sourceCidr;
    }
    /**
     * @return Optional and valid only for TCP. Use to specify particular destination ports for TCP rules. If you specify TCP as the protocol but omit this object, then all destination ports are allowed.
     * 
     */
    public List<GetCaptureFilterVtapCaptureFilterRuleTcpOption> tcpOptions() {
        return this.tcpOptions;
    }
    /**
     * @return The traffic direction the VTAP is configured to mirror.
     * 
     */
    public String trafficDirection() {
        return this.trafficDirection;
    }
    /**
     * @return Optional and valid only for UDP. Use to specify particular destination ports for UDP rules. If you specify UDP as the protocol but omit this object, then all destination ports are allowed.
     * 
     */
    public List<GetCaptureFilterVtapCaptureFilterRuleUdpOption> udpOptions() {
        return this.udpOptions;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetCaptureFilterVtapCaptureFilterRule defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String destinationCidr;
        private List<GetCaptureFilterVtapCaptureFilterRuleIcmpOption> icmpOptions;
        private String protocol;
        private String ruleAction;
        private String sourceCidr;
        private List<GetCaptureFilterVtapCaptureFilterRuleTcpOption> tcpOptions;
        private String trafficDirection;
        private List<GetCaptureFilterVtapCaptureFilterRuleUdpOption> udpOptions;
        public Builder() {}
        public Builder(GetCaptureFilterVtapCaptureFilterRule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.destinationCidr = defaults.destinationCidr;
    	      this.icmpOptions = defaults.icmpOptions;
    	      this.protocol = defaults.protocol;
    	      this.ruleAction = defaults.ruleAction;
    	      this.sourceCidr = defaults.sourceCidr;
    	      this.tcpOptions = defaults.tcpOptions;
    	      this.trafficDirection = defaults.trafficDirection;
    	      this.udpOptions = defaults.udpOptions;
        }

        @CustomType.Setter
        public Builder destinationCidr(String destinationCidr) {
            this.destinationCidr = Objects.requireNonNull(destinationCidr);
            return this;
        }
        @CustomType.Setter
        public Builder icmpOptions(List<GetCaptureFilterVtapCaptureFilterRuleIcmpOption> icmpOptions) {
            this.icmpOptions = Objects.requireNonNull(icmpOptions);
            return this;
        }
        public Builder icmpOptions(GetCaptureFilterVtapCaptureFilterRuleIcmpOption... icmpOptions) {
            return icmpOptions(List.of(icmpOptions));
        }
        @CustomType.Setter
        public Builder protocol(String protocol) {
            this.protocol = Objects.requireNonNull(protocol);
            return this;
        }
        @CustomType.Setter
        public Builder ruleAction(String ruleAction) {
            this.ruleAction = Objects.requireNonNull(ruleAction);
            return this;
        }
        @CustomType.Setter
        public Builder sourceCidr(String sourceCidr) {
            this.sourceCidr = Objects.requireNonNull(sourceCidr);
            return this;
        }
        @CustomType.Setter
        public Builder tcpOptions(List<GetCaptureFilterVtapCaptureFilterRuleTcpOption> tcpOptions) {
            this.tcpOptions = Objects.requireNonNull(tcpOptions);
            return this;
        }
        public Builder tcpOptions(GetCaptureFilterVtapCaptureFilterRuleTcpOption... tcpOptions) {
            return tcpOptions(List.of(tcpOptions));
        }
        @CustomType.Setter
        public Builder trafficDirection(String trafficDirection) {
            this.trafficDirection = Objects.requireNonNull(trafficDirection);
            return this;
        }
        @CustomType.Setter
        public Builder udpOptions(List<GetCaptureFilterVtapCaptureFilterRuleUdpOption> udpOptions) {
            this.udpOptions = Objects.requireNonNull(udpOptions);
            return this;
        }
        public Builder udpOptions(GetCaptureFilterVtapCaptureFilterRuleUdpOption... udpOptions) {
            return udpOptions(List.of(udpOptions));
        }
        public GetCaptureFilterVtapCaptureFilterRule build() {
            final var o = new GetCaptureFilterVtapCaptureFilterRule();
            o.destinationCidr = destinationCidr;
            o.icmpOptions = icmpOptions;
            o.protocol = protocol;
            o.ruleAction = ruleAction;
            o.sourceCidr = sourceCidr;
            o.tcpOptions = tcpOptions;
            o.trafficDirection = trafficDirection;
            o.udpOptions = udpOptions;
            return o;
        }
    }
}