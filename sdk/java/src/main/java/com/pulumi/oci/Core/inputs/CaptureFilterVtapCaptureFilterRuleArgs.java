// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Core.inputs.CaptureFilterVtapCaptureFilterRuleIcmpOptionsArgs;
import com.pulumi.oci.Core.inputs.CaptureFilterVtapCaptureFilterRuleTcpOptionsArgs;
import com.pulumi.oci.Core.inputs.CaptureFilterVtapCaptureFilterRuleUdpOptionsArgs;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class CaptureFilterVtapCaptureFilterRuleArgs extends com.pulumi.resources.ResourceArgs {

    public static final CaptureFilterVtapCaptureFilterRuleArgs Empty = new CaptureFilterVtapCaptureFilterRuleArgs();

    /**
     * (Updatable) Traffic sent to this CIDR block through the VTAP source will be mirrored to the VTAP target.
     * 
     */
    @Import(name="destinationCidr")
    private @Nullable Output<String> destinationCidr;

    /**
     * @return (Updatable) Traffic sent to this CIDR block through the VTAP source will be mirrored to the VTAP target.
     * 
     */
    public Optional<Output<String>> destinationCidr() {
        return Optional.ofNullable(this.destinationCidr);
    }

    /**
     * (Updatable) Optional and valid only for ICMP and ICMPv6. Use to specify a particular ICMP type and code as defined in:
     * * [ICMP Parameters](http://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml)
     * * [ICMPv6 Parameters](https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml)
     * 
     * If you specify ICMP or ICMPv6 as the protocol but omit this object, then all ICMP types and codes are allowed. If you do provide this object, the type is required and the code is optional. To enable MTU negotiation for ingress internet traffic via IPv4, make sure to allow type 3 (&#34;Destination Unreachable&#34;) code 4 (&#34;Fragmentation Needed and Don&#39;t Fragment was Set&#34;). If you need to specify multiple codes for a single type, create a separate security list rule for each.
     * 
     */
    @Import(name="icmpOptions")
    private @Nullable Output<CaptureFilterVtapCaptureFilterRuleIcmpOptionsArgs> icmpOptions;

    /**
     * @return (Updatable) Optional and valid only for ICMP and ICMPv6. Use to specify a particular ICMP type and code as defined in:
     * * [ICMP Parameters](http://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml)
     * * [ICMPv6 Parameters](https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml)
     * 
     * If you specify ICMP or ICMPv6 as the protocol but omit this object, then all ICMP types and codes are allowed. If you do provide this object, the type is required and the code is optional. To enable MTU negotiation for ingress internet traffic via IPv4, make sure to allow type 3 (&#34;Destination Unreachable&#34;) code 4 (&#34;Fragmentation Needed and Don&#39;t Fragment was Set&#34;). If you need to specify multiple codes for a single type, create a separate security list rule for each.
     * 
     */
    public Optional<Output<CaptureFilterVtapCaptureFilterRuleIcmpOptionsArgs>> icmpOptions() {
        return Optional.ofNullable(this.icmpOptions);
    }

    /**
     * (Updatable) The transport protocol used in the filter. If do not choose a protocol, all protocols will be used in the filter. Supported options are:
     * * 1 = ICMP
     * * 6 = TCP
     * * 17 = UDP
     * 
     */
    @Import(name="protocol")
    private @Nullable Output<String> protocol;

    /**
     * @return (Updatable) The transport protocol used in the filter. If do not choose a protocol, all protocols will be used in the filter. Supported options are:
     * * 1 = ICMP
     * * 6 = TCP
     * * 17 = UDP
     * 
     */
    public Optional<Output<String>> protocol() {
        return Optional.ofNullable(this.protocol);
    }

    /**
     * (Updatable) Include or exclude packets meeting this definition from mirrored traffic.
     * 
     */
    @Import(name="ruleAction")
    private @Nullable Output<String> ruleAction;

    /**
     * @return (Updatable) Include or exclude packets meeting this definition from mirrored traffic.
     * 
     */
    public Optional<Output<String>> ruleAction() {
        return Optional.ofNullable(this.ruleAction);
    }

    /**
     * (Updatable) Traffic from this CIDR block to the VTAP source will be mirrored to the VTAP target.
     * 
     */
    @Import(name="sourceCidr")
    private @Nullable Output<String> sourceCidr;

    /**
     * @return (Updatable) Traffic from this CIDR block to the VTAP source will be mirrored to the VTAP target.
     * 
     */
    public Optional<Output<String>> sourceCidr() {
        return Optional.ofNullable(this.sourceCidr);
    }

    /**
     * (Updatable) Optional and valid only for TCP. Use to specify particular destination ports for TCP rules. If you specify TCP as the protocol but omit this object, then all destination ports are allowed.
     * 
     */
    @Import(name="tcpOptions")
    private @Nullable Output<CaptureFilterVtapCaptureFilterRuleTcpOptionsArgs> tcpOptions;

    /**
     * @return (Updatable) Optional and valid only for TCP. Use to specify particular destination ports for TCP rules. If you specify TCP as the protocol but omit this object, then all destination ports are allowed.
     * 
     */
    public Optional<Output<CaptureFilterVtapCaptureFilterRuleTcpOptionsArgs>> tcpOptions() {
        return Optional.ofNullable(this.tcpOptions);
    }

    /**
     * (Updatable) The traffic direction the VTAP is configured to mirror.
     * 
     */
    @Import(name="trafficDirection", required=true)
    private Output<String> trafficDirection;

    /**
     * @return (Updatable) The traffic direction the VTAP is configured to mirror.
     * 
     */
    public Output<String> trafficDirection() {
        return this.trafficDirection;
    }

    /**
     * (Updatable) Optional and valid only for UDP. Use to specify particular destination ports for UDP rules. If you specify UDP as the protocol but omit this object, then all destination ports are allowed.
     * 
     */
    @Import(name="udpOptions")
    private @Nullable Output<CaptureFilterVtapCaptureFilterRuleUdpOptionsArgs> udpOptions;

    /**
     * @return (Updatable) Optional and valid only for UDP. Use to specify particular destination ports for UDP rules. If you specify UDP as the protocol but omit this object, then all destination ports are allowed.
     * 
     */
    public Optional<Output<CaptureFilterVtapCaptureFilterRuleUdpOptionsArgs>> udpOptions() {
        return Optional.ofNullable(this.udpOptions);
    }

    private CaptureFilterVtapCaptureFilterRuleArgs() {}

    private CaptureFilterVtapCaptureFilterRuleArgs(CaptureFilterVtapCaptureFilterRuleArgs $) {
        this.destinationCidr = $.destinationCidr;
        this.icmpOptions = $.icmpOptions;
        this.protocol = $.protocol;
        this.ruleAction = $.ruleAction;
        this.sourceCidr = $.sourceCidr;
        this.tcpOptions = $.tcpOptions;
        this.trafficDirection = $.trafficDirection;
        this.udpOptions = $.udpOptions;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(CaptureFilterVtapCaptureFilterRuleArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private CaptureFilterVtapCaptureFilterRuleArgs $;

        public Builder() {
            $ = new CaptureFilterVtapCaptureFilterRuleArgs();
        }

        public Builder(CaptureFilterVtapCaptureFilterRuleArgs defaults) {
            $ = new CaptureFilterVtapCaptureFilterRuleArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param destinationCidr (Updatable) Traffic sent to this CIDR block through the VTAP source will be mirrored to the VTAP target.
         * 
         * @return builder
         * 
         */
        public Builder destinationCidr(@Nullable Output<String> destinationCidr) {
            $.destinationCidr = destinationCidr;
            return this;
        }

        /**
         * @param destinationCidr (Updatable) Traffic sent to this CIDR block through the VTAP source will be mirrored to the VTAP target.
         * 
         * @return builder
         * 
         */
        public Builder destinationCidr(String destinationCidr) {
            return destinationCidr(Output.of(destinationCidr));
        }

        /**
         * @param icmpOptions (Updatable) Optional and valid only for ICMP and ICMPv6. Use to specify a particular ICMP type and code as defined in:
         * * [ICMP Parameters](http://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml)
         * * [ICMPv6 Parameters](https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml)
         * 
         * If you specify ICMP or ICMPv6 as the protocol but omit this object, then all ICMP types and codes are allowed. If you do provide this object, the type is required and the code is optional. To enable MTU negotiation for ingress internet traffic via IPv4, make sure to allow type 3 (&#34;Destination Unreachable&#34;) code 4 (&#34;Fragmentation Needed and Don&#39;t Fragment was Set&#34;). If you need to specify multiple codes for a single type, create a separate security list rule for each.
         * 
         * @return builder
         * 
         */
        public Builder icmpOptions(@Nullable Output<CaptureFilterVtapCaptureFilterRuleIcmpOptionsArgs> icmpOptions) {
            $.icmpOptions = icmpOptions;
            return this;
        }

        /**
         * @param icmpOptions (Updatable) Optional and valid only for ICMP and ICMPv6. Use to specify a particular ICMP type and code as defined in:
         * * [ICMP Parameters](http://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml)
         * * [ICMPv6 Parameters](https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml)
         * 
         * If you specify ICMP or ICMPv6 as the protocol but omit this object, then all ICMP types and codes are allowed. If you do provide this object, the type is required and the code is optional. To enable MTU negotiation for ingress internet traffic via IPv4, make sure to allow type 3 (&#34;Destination Unreachable&#34;) code 4 (&#34;Fragmentation Needed and Don&#39;t Fragment was Set&#34;). If you need to specify multiple codes for a single type, create a separate security list rule for each.
         * 
         * @return builder
         * 
         */
        public Builder icmpOptions(CaptureFilterVtapCaptureFilterRuleIcmpOptionsArgs icmpOptions) {
            return icmpOptions(Output.of(icmpOptions));
        }

        /**
         * @param protocol (Updatable) The transport protocol used in the filter. If do not choose a protocol, all protocols will be used in the filter. Supported options are:
         * * 1 = ICMP
         * * 6 = TCP
         * * 17 = UDP
         * 
         * @return builder
         * 
         */
        public Builder protocol(@Nullable Output<String> protocol) {
            $.protocol = protocol;
            return this;
        }

        /**
         * @param protocol (Updatable) The transport protocol used in the filter. If do not choose a protocol, all protocols will be used in the filter. Supported options are:
         * * 1 = ICMP
         * * 6 = TCP
         * * 17 = UDP
         * 
         * @return builder
         * 
         */
        public Builder protocol(String protocol) {
            return protocol(Output.of(protocol));
        }

        /**
         * @param ruleAction (Updatable) Include or exclude packets meeting this definition from mirrored traffic.
         * 
         * @return builder
         * 
         */
        public Builder ruleAction(@Nullable Output<String> ruleAction) {
            $.ruleAction = ruleAction;
            return this;
        }

        /**
         * @param ruleAction (Updatable) Include or exclude packets meeting this definition from mirrored traffic.
         * 
         * @return builder
         * 
         */
        public Builder ruleAction(String ruleAction) {
            return ruleAction(Output.of(ruleAction));
        }

        /**
         * @param sourceCidr (Updatable) Traffic from this CIDR block to the VTAP source will be mirrored to the VTAP target.
         * 
         * @return builder
         * 
         */
        public Builder sourceCidr(@Nullable Output<String> sourceCidr) {
            $.sourceCidr = sourceCidr;
            return this;
        }

        /**
         * @param sourceCidr (Updatable) Traffic from this CIDR block to the VTAP source will be mirrored to the VTAP target.
         * 
         * @return builder
         * 
         */
        public Builder sourceCidr(String sourceCidr) {
            return sourceCidr(Output.of(sourceCidr));
        }

        /**
         * @param tcpOptions (Updatable) Optional and valid only for TCP. Use to specify particular destination ports for TCP rules. If you specify TCP as the protocol but omit this object, then all destination ports are allowed.
         * 
         * @return builder
         * 
         */
        public Builder tcpOptions(@Nullable Output<CaptureFilterVtapCaptureFilterRuleTcpOptionsArgs> tcpOptions) {
            $.tcpOptions = tcpOptions;
            return this;
        }

        /**
         * @param tcpOptions (Updatable) Optional and valid only for TCP. Use to specify particular destination ports for TCP rules. If you specify TCP as the protocol but omit this object, then all destination ports are allowed.
         * 
         * @return builder
         * 
         */
        public Builder tcpOptions(CaptureFilterVtapCaptureFilterRuleTcpOptionsArgs tcpOptions) {
            return tcpOptions(Output.of(tcpOptions));
        }

        /**
         * @param trafficDirection (Updatable) The traffic direction the VTAP is configured to mirror.
         * 
         * @return builder
         * 
         */
        public Builder trafficDirection(Output<String> trafficDirection) {
            $.trafficDirection = trafficDirection;
            return this;
        }

        /**
         * @param trafficDirection (Updatable) The traffic direction the VTAP is configured to mirror.
         * 
         * @return builder
         * 
         */
        public Builder trafficDirection(String trafficDirection) {
            return trafficDirection(Output.of(trafficDirection));
        }

        /**
         * @param udpOptions (Updatable) Optional and valid only for UDP. Use to specify particular destination ports for UDP rules. If you specify UDP as the protocol but omit this object, then all destination ports are allowed.
         * 
         * @return builder
         * 
         */
        public Builder udpOptions(@Nullable Output<CaptureFilterVtapCaptureFilterRuleUdpOptionsArgs> udpOptions) {
            $.udpOptions = udpOptions;
            return this;
        }

        /**
         * @param udpOptions (Updatable) Optional and valid only for UDP. Use to specify particular destination ports for UDP rules. If you specify UDP as the protocol but omit this object, then all destination ports are allowed.
         * 
         * @return builder
         * 
         */
        public Builder udpOptions(CaptureFilterVtapCaptureFilterRuleUdpOptionsArgs udpOptions) {
            return udpOptions(Output.of(udpOptions));
        }

        public CaptureFilterVtapCaptureFilterRuleArgs build() {
            if ($.trafficDirection == null) {
                throw new MissingRequiredPropertyException("CaptureFilterVtapCaptureFilterRuleArgs", "trafficDirection");
            }
            return $;
        }
    }

}
