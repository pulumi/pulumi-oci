// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Core.inputs.IpsecConnectionTunnelManagementBgpSessionInfoArgs;
import com.pulumi.oci.Core.inputs.IpsecConnectionTunnelManagementDpdConfigArgs;
import com.pulumi.oci.Core.inputs.IpsecConnectionTunnelManagementEncryptionDomainConfigArgs;
import com.pulumi.oci.Core.inputs.IpsecConnectionTunnelManagementPhaseOneDetailsArgs;
import com.pulumi.oci.Core.inputs.IpsecConnectionTunnelManagementPhaseTwoDetailsArgs;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class IpsecConnectionTunnelManagementState extends com.pulumi.resources.ResourceArgs {

    public static final IpsecConnectionTunnelManagementState Empty = new IpsecConnectionTunnelManagementState();

    /**
     * The list of virtual circuit [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)s over which your network can reach this tunnel.
     * 
     */
    @Import(name="associatedVirtualCircuits")
    private @Nullable Output<List<String>> associatedVirtualCircuits;

    /**
     * @return The list of virtual circuit [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)s over which your network can reach this tunnel.
     * 
     */
    public Optional<Output<List<String>>> associatedVirtualCircuits() {
        return Optional.ofNullable(this.associatedVirtualCircuits);
    }

    /**
     * Information for establishing a BGP session for the IPSec tunnel. Required if the tunnel uses BGP dynamic routing.
     * 
     * If the tunnel instead uses static routing, you may optionally provide this object and set an IP address for one or both ends of the IPSec tunnel for the purposes of troubleshooting or monitoring the tunnel.
     * 
     */
    @Import(name="bgpSessionInfo")
    private @Nullable Output<IpsecConnectionTunnelManagementBgpSessionInfoArgs> bgpSessionInfo;

    /**
     * @return Information for establishing a BGP session for the IPSec tunnel. Required if the tunnel uses BGP dynamic routing.
     * 
     * If the tunnel instead uses static routing, you may optionally provide this object and set an IP address for one or both ends of the IPSec tunnel for the purposes of troubleshooting or monitoring the tunnel.
     * 
     */
    public Optional<Output<IpsecConnectionTunnelManagementBgpSessionInfoArgs>> bgpSessionInfo() {
        return Optional.ofNullable(this.bgpSessionInfo);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the tunnel.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the tunnel.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * The IP address of the CPE device&#39;s VPN headend.  Example: `203.0.113.22`
     * 
     */
    @Import(name="cpeIp")
    private @Nullable Output<String> cpeIp;

    /**
     * @return The IP address of the CPE device&#39;s VPN headend.  Example: `203.0.113.22`
     * 
     */
    public Optional<Output<String>> cpeIp() {
        return Optional.ofNullable(this.cpeIp);
    }

    /**
     * A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="dpdConfigs")
    private @Nullable Output<List<IpsecConnectionTunnelManagementDpdConfigArgs>> dpdConfigs;

    public Optional<Output<List<IpsecConnectionTunnelManagementDpdConfigArgs>>> dpdConfigs() {
        return Optional.ofNullable(this.dpdConfigs);
    }

    /**
     * Dead peer detection (DPD) mode set on the Oracle side of the connection.
     * 
     */
    @Import(name="dpdMode")
    private @Nullable Output<String> dpdMode;

    /**
     * @return Dead peer detection (DPD) mode set on the Oracle side of the connection.
     * 
     */
    public Optional<Output<String>> dpdMode() {
        return Optional.ofNullable(this.dpdMode);
    }

    /**
     * DPD timeout in seconds.
     * 
     */
    @Import(name="dpdTimeoutInSec")
    private @Nullable Output<Integer> dpdTimeoutInSec;

    /**
     * @return DPD timeout in seconds.
     * 
     */
    public Optional<Output<Integer>> dpdTimeoutInSec() {
        return Optional.ofNullable(this.dpdTimeoutInSec);
    }

    /**
     * Configuration information used by the encryption domain policy. Required if the tunnel uses POLICY routing.
     * 
     */
    @Import(name="encryptionDomainConfig")
    private @Nullable Output<IpsecConnectionTunnelManagementEncryptionDomainConfigArgs> encryptionDomainConfig;

    /**
     * @return Configuration information used by the encryption domain policy. Required if the tunnel uses POLICY routing.
     * 
     */
    public Optional<Output<IpsecConnectionTunnelManagementEncryptionDomainConfigArgs>> encryptionDomainConfig() {
        return Optional.ofNullable(this.encryptionDomainConfig);
    }

    /**
     * Internet Key Exchange protocol version.
     * 
     */
    @Import(name="ikeVersion")
    private @Nullable Output<String> ikeVersion;

    /**
     * @return Internet Key Exchange protocol version.
     * 
     */
    public Optional<Output<String>> ikeVersion() {
        return Optional.ofNullable(this.ikeVersion);
    }

    /**
     * The OCID of the IPSec connection.
     * 
     */
    @Import(name="ipsecId")
    private @Nullable Output<String> ipsecId;

    /**
     * @return The OCID of the IPSec connection.
     * 
     */
    public Optional<Output<String>> ipsecId() {
        return Optional.ofNullable(this.ipsecId);
    }

    /**
     * By default (the `AUTO` setting), IKE sends packets with a source and destination port set to 500, and when it detects that the port used to forward packets has changed (most likely because a NAT device is between the CPE device and the Oracle VPN headend) it will try to negotiate the use of NAT-T.
     * 
     * The `ENABLED` option sets the IKE protocol to use port 4500 instead of 500 and forces encapsulating traffic with the ESP protocol inside UDP packets.
     * 
     * The `DISABLED` option directs IKE to completely refuse to negotiate NAT-T even if it senses there may be a NAT device in use.
     * 
     */
    @Import(name="natTranslationEnabled")
    private @Nullable Output<String> natTranslationEnabled;

    /**
     * @return By default (the `AUTO` setting), IKE sends packets with a source and destination port set to 500, and when it detects that the port used to forward packets has changed (most likely because a NAT device is between the CPE device and the Oracle VPN headend) it will try to negotiate the use of NAT-T.
     * 
     * The `ENABLED` option sets the IKE protocol to use port 4500 instead of 500 and forces encapsulating traffic with the ESP protocol inside UDP packets.
     * 
     * The `DISABLED` option directs IKE to completely refuse to negotiate NAT-T even if it senses there may be a NAT device in use.
     * 
     */
    public Optional<Output<String>> natTranslationEnabled() {
        return Optional.ofNullable(this.natTranslationEnabled);
    }

    /**
     * Indicates whether Oracle can only respond to a request to start an IPSec tunnel from the CPE device (`RESPONDER_ONLY`), or both respond to and initiate requests (`INITIATOR_OR_RESPONDER`).
     * 
     */
    @Import(name="oracleCanInitiate")
    private @Nullable Output<String> oracleCanInitiate;

    /**
     * @return Indicates whether Oracle can only respond to a request to start an IPSec tunnel from the CPE device (`RESPONDER_ONLY`), or both respond to and initiate requests (`INITIATOR_OR_RESPONDER`).
     * 
     */
    public Optional<Output<String>> oracleCanInitiate() {
        return Optional.ofNullable(this.oracleCanInitiate);
    }

    /**
     * Configuration details for IKE phase one (ISAKMP) configuration parameters.
     * 
     * See [PhaseOneConfigDetails](https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/datatypes/PhaseOneConfigDetails) for allowed values but note naming scheme follows [TunnelPhaseOneDetails](https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/datatypes/TunnelPhaseOneDetails).
     * 
     */
    @Import(name="phaseOneDetails")
    private @Nullable Output<IpsecConnectionTunnelManagementPhaseOneDetailsArgs> phaseOneDetails;

    /**
     * @return Configuration details for IKE phase one (ISAKMP) configuration parameters.
     * 
     * See [PhaseOneConfigDetails](https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/datatypes/PhaseOneConfigDetails) for allowed values but note naming scheme follows [TunnelPhaseOneDetails](https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/datatypes/TunnelPhaseOneDetails).
     * 
     */
    public Optional<Output<IpsecConnectionTunnelManagementPhaseOneDetailsArgs>> phaseOneDetails() {
        return Optional.ofNullable(this.phaseOneDetails);
    }

    /**
     * Configuration details for IPSec phase two configuration parameters.
     * 
     * See [PhaseTwoConfigDetails](https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/datatypes/PhaseTwoConfigDetails) for allowed values, but note naming scheme follows [TunnelPhaseTwoDetails](https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/datatypes/TunnelPhaseTwoDetails).
     * 
     */
    @Import(name="phaseTwoDetails")
    private @Nullable Output<IpsecConnectionTunnelManagementPhaseTwoDetailsArgs> phaseTwoDetails;

    /**
     * @return Configuration details for IPSec phase two configuration parameters.
     * 
     * See [PhaseTwoConfigDetails](https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/datatypes/PhaseTwoConfigDetails) for allowed values, but note naming scheme follows [TunnelPhaseTwoDetails](https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/datatypes/TunnelPhaseTwoDetails).
     * 
     */
    public Optional<Output<IpsecConnectionTunnelManagementPhaseTwoDetailsArgs>> phaseTwoDetails() {
        return Optional.ofNullable(this.phaseTwoDetails);
    }

    /**
     * The type of routing to use for this tunnel (either BGP dynamic routing, STATIC routing or POLICY routing).
     * 
     */
    @Import(name="routing")
    private @Nullable Output<String> routing;

    /**
     * @return The type of routing to use for this tunnel (either BGP dynamic routing, STATIC routing or POLICY routing).
     * 
     */
    public Optional<Output<String>> routing() {
        return Optional.ofNullable(this.routing);
    }

    /**
     * The shared secret (pre-shared key) to use for the IPSec tunnel. If you don&#39;t provide a value, Oracle generates a value for you. You can specify your own shared secret later if you like with [UpdateIPSecConnectionTunnelSharedSecret](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/IPSecConnectionTunnelSharedSecret/UpdateIPSecConnectionTunnelSharedSecret).  Example: `EXAMPLEToUis6j1c.p8G.dVQxcmdfMO0yXMLi.lZTbYCMDGu4V8o`
     * 
     */
    @Import(name="sharedSecret")
    private @Nullable Output<String> sharedSecret;

    /**
     * @return The shared secret (pre-shared key) to use for the IPSec tunnel. If you don&#39;t provide a value, Oracle generates a value for you. You can specify your own shared secret later if you like with [UpdateIPSecConnectionTunnelSharedSecret](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/IPSecConnectionTunnelSharedSecret/UpdateIPSecConnectionTunnelSharedSecret).  Example: `EXAMPLEToUis6j1c.p8G.dVQxcmdfMO0yXMLi.lZTbYCMDGu4V8o`
     * 
     */
    public Optional<Output<String>> sharedSecret() {
        return Optional.ofNullable(this.sharedSecret);
    }

    /**
     * The IPSec connection&#39;s tunnel&#39;s lifecycle state.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The IPSec connection&#39;s tunnel&#39;s lifecycle state.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The tunnel&#39;s current state.
     * 
     */
    @Import(name="status")
    private @Nullable Output<String> status;

    /**
     * @return The tunnel&#39;s current state.
     * 
     */
    public Optional<Output<String>> status() {
        return Optional.ofNullable(this.status);
    }

    /**
     * The date and time the IPSec connection tunnel was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time the IPSec connection tunnel was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * When the status of the tunnel last changed, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Import(name="timeStatusUpdated")
    private @Nullable Output<String> timeStatusUpdated;

    /**
     * @return When the status of the tunnel last changed, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Optional<Output<String>> timeStatusUpdated() {
        return Optional.ofNullable(this.timeStatusUpdated);
    }

    /**
     * The OCID of the IPSec connection&#39;s tunnel.
     * 
     */
    @Import(name="tunnelId")
    private @Nullable Output<String> tunnelId;

    /**
     * @return The OCID of the IPSec connection&#39;s tunnel.
     * 
     */
    public Optional<Output<String>> tunnelId() {
        return Optional.ofNullable(this.tunnelId);
    }

    /**
     * The IP address of Oracle&#39;s VPN headend.  Example: `129.146.17.50`
     * 
     */
    @Import(name="vpnIp")
    private @Nullable Output<String> vpnIp;

    /**
     * @return The IP address of Oracle&#39;s VPN headend.  Example: `129.146.17.50`
     * 
     */
    public Optional<Output<String>> vpnIp() {
        return Optional.ofNullable(this.vpnIp);
    }

    private IpsecConnectionTunnelManagementState() {}

    private IpsecConnectionTunnelManagementState(IpsecConnectionTunnelManagementState $) {
        this.associatedVirtualCircuits = $.associatedVirtualCircuits;
        this.bgpSessionInfo = $.bgpSessionInfo;
        this.compartmentId = $.compartmentId;
        this.cpeIp = $.cpeIp;
        this.displayName = $.displayName;
        this.dpdConfigs = $.dpdConfigs;
        this.dpdMode = $.dpdMode;
        this.dpdTimeoutInSec = $.dpdTimeoutInSec;
        this.encryptionDomainConfig = $.encryptionDomainConfig;
        this.ikeVersion = $.ikeVersion;
        this.ipsecId = $.ipsecId;
        this.natTranslationEnabled = $.natTranslationEnabled;
        this.oracleCanInitiate = $.oracleCanInitiate;
        this.phaseOneDetails = $.phaseOneDetails;
        this.phaseTwoDetails = $.phaseTwoDetails;
        this.routing = $.routing;
        this.sharedSecret = $.sharedSecret;
        this.state = $.state;
        this.status = $.status;
        this.timeCreated = $.timeCreated;
        this.timeStatusUpdated = $.timeStatusUpdated;
        this.tunnelId = $.tunnelId;
        this.vpnIp = $.vpnIp;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(IpsecConnectionTunnelManagementState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private IpsecConnectionTunnelManagementState $;

        public Builder() {
            $ = new IpsecConnectionTunnelManagementState();
        }

        public Builder(IpsecConnectionTunnelManagementState defaults) {
            $ = new IpsecConnectionTunnelManagementState(Objects.requireNonNull(defaults));
        }

        /**
         * @param associatedVirtualCircuits The list of virtual circuit [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)s over which your network can reach this tunnel.
         * 
         * @return builder
         * 
         */
        public Builder associatedVirtualCircuits(@Nullable Output<List<String>> associatedVirtualCircuits) {
            $.associatedVirtualCircuits = associatedVirtualCircuits;
            return this;
        }

        /**
         * @param associatedVirtualCircuits The list of virtual circuit [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)s over which your network can reach this tunnel.
         * 
         * @return builder
         * 
         */
        public Builder associatedVirtualCircuits(List<String> associatedVirtualCircuits) {
            return associatedVirtualCircuits(Output.of(associatedVirtualCircuits));
        }

        /**
         * @param associatedVirtualCircuits The list of virtual circuit [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)s over which your network can reach this tunnel.
         * 
         * @return builder
         * 
         */
        public Builder associatedVirtualCircuits(String... associatedVirtualCircuits) {
            return associatedVirtualCircuits(List.of(associatedVirtualCircuits));
        }

        /**
         * @param bgpSessionInfo Information for establishing a BGP session for the IPSec tunnel. Required if the tunnel uses BGP dynamic routing.
         * 
         * If the tunnel instead uses static routing, you may optionally provide this object and set an IP address for one or both ends of the IPSec tunnel for the purposes of troubleshooting or monitoring the tunnel.
         * 
         * @return builder
         * 
         */
        public Builder bgpSessionInfo(@Nullable Output<IpsecConnectionTunnelManagementBgpSessionInfoArgs> bgpSessionInfo) {
            $.bgpSessionInfo = bgpSessionInfo;
            return this;
        }

        /**
         * @param bgpSessionInfo Information for establishing a BGP session for the IPSec tunnel. Required if the tunnel uses BGP dynamic routing.
         * 
         * If the tunnel instead uses static routing, you may optionally provide this object and set an IP address for one or both ends of the IPSec tunnel for the purposes of troubleshooting or monitoring the tunnel.
         * 
         * @return builder
         * 
         */
        public Builder bgpSessionInfo(IpsecConnectionTunnelManagementBgpSessionInfoArgs bgpSessionInfo) {
            return bgpSessionInfo(Output.of(bgpSessionInfo));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the tunnel.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the tunnel.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param cpeIp The IP address of the CPE device&#39;s VPN headend.  Example: `203.0.113.22`
         * 
         * @return builder
         * 
         */
        public Builder cpeIp(@Nullable Output<String> cpeIp) {
            $.cpeIp = cpeIp;
            return this;
        }

        /**
         * @param cpeIp The IP address of the CPE device&#39;s VPN headend.  Example: `203.0.113.22`
         * 
         * @return builder
         * 
         */
        public Builder cpeIp(String cpeIp) {
            return cpeIp(Output.of(cpeIp));
        }

        /**
         * @param displayName A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder dpdConfigs(@Nullable Output<List<IpsecConnectionTunnelManagementDpdConfigArgs>> dpdConfigs) {
            $.dpdConfigs = dpdConfigs;
            return this;
        }

        public Builder dpdConfigs(List<IpsecConnectionTunnelManagementDpdConfigArgs> dpdConfigs) {
            return dpdConfigs(Output.of(dpdConfigs));
        }

        public Builder dpdConfigs(IpsecConnectionTunnelManagementDpdConfigArgs... dpdConfigs) {
            return dpdConfigs(List.of(dpdConfigs));
        }

        /**
         * @param dpdMode Dead peer detection (DPD) mode set on the Oracle side of the connection.
         * 
         * @return builder
         * 
         */
        public Builder dpdMode(@Nullable Output<String> dpdMode) {
            $.dpdMode = dpdMode;
            return this;
        }

        /**
         * @param dpdMode Dead peer detection (DPD) mode set on the Oracle side of the connection.
         * 
         * @return builder
         * 
         */
        public Builder dpdMode(String dpdMode) {
            return dpdMode(Output.of(dpdMode));
        }

        /**
         * @param dpdTimeoutInSec DPD timeout in seconds.
         * 
         * @return builder
         * 
         */
        public Builder dpdTimeoutInSec(@Nullable Output<Integer> dpdTimeoutInSec) {
            $.dpdTimeoutInSec = dpdTimeoutInSec;
            return this;
        }

        /**
         * @param dpdTimeoutInSec DPD timeout in seconds.
         * 
         * @return builder
         * 
         */
        public Builder dpdTimeoutInSec(Integer dpdTimeoutInSec) {
            return dpdTimeoutInSec(Output.of(dpdTimeoutInSec));
        }

        /**
         * @param encryptionDomainConfig Configuration information used by the encryption domain policy. Required if the tunnel uses POLICY routing.
         * 
         * @return builder
         * 
         */
        public Builder encryptionDomainConfig(@Nullable Output<IpsecConnectionTunnelManagementEncryptionDomainConfigArgs> encryptionDomainConfig) {
            $.encryptionDomainConfig = encryptionDomainConfig;
            return this;
        }

        /**
         * @param encryptionDomainConfig Configuration information used by the encryption domain policy. Required if the tunnel uses POLICY routing.
         * 
         * @return builder
         * 
         */
        public Builder encryptionDomainConfig(IpsecConnectionTunnelManagementEncryptionDomainConfigArgs encryptionDomainConfig) {
            return encryptionDomainConfig(Output.of(encryptionDomainConfig));
        }

        /**
         * @param ikeVersion Internet Key Exchange protocol version.
         * 
         * @return builder
         * 
         */
        public Builder ikeVersion(@Nullable Output<String> ikeVersion) {
            $.ikeVersion = ikeVersion;
            return this;
        }

        /**
         * @param ikeVersion Internet Key Exchange protocol version.
         * 
         * @return builder
         * 
         */
        public Builder ikeVersion(String ikeVersion) {
            return ikeVersion(Output.of(ikeVersion));
        }

        /**
         * @param ipsecId The OCID of the IPSec connection.
         * 
         * @return builder
         * 
         */
        public Builder ipsecId(@Nullable Output<String> ipsecId) {
            $.ipsecId = ipsecId;
            return this;
        }

        /**
         * @param ipsecId The OCID of the IPSec connection.
         * 
         * @return builder
         * 
         */
        public Builder ipsecId(String ipsecId) {
            return ipsecId(Output.of(ipsecId));
        }

        /**
         * @param natTranslationEnabled By default (the `AUTO` setting), IKE sends packets with a source and destination port set to 500, and when it detects that the port used to forward packets has changed (most likely because a NAT device is between the CPE device and the Oracle VPN headend) it will try to negotiate the use of NAT-T.
         * 
         * The `ENABLED` option sets the IKE protocol to use port 4500 instead of 500 and forces encapsulating traffic with the ESP protocol inside UDP packets.
         * 
         * The `DISABLED` option directs IKE to completely refuse to negotiate NAT-T even if it senses there may be a NAT device in use.
         * 
         * @return builder
         * 
         */
        public Builder natTranslationEnabled(@Nullable Output<String> natTranslationEnabled) {
            $.natTranslationEnabled = natTranslationEnabled;
            return this;
        }

        /**
         * @param natTranslationEnabled By default (the `AUTO` setting), IKE sends packets with a source and destination port set to 500, and when it detects that the port used to forward packets has changed (most likely because a NAT device is between the CPE device and the Oracle VPN headend) it will try to negotiate the use of NAT-T.
         * 
         * The `ENABLED` option sets the IKE protocol to use port 4500 instead of 500 and forces encapsulating traffic with the ESP protocol inside UDP packets.
         * 
         * The `DISABLED` option directs IKE to completely refuse to negotiate NAT-T even if it senses there may be a NAT device in use.
         * 
         * @return builder
         * 
         */
        public Builder natTranslationEnabled(String natTranslationEnabled) {
            return natTranslationEnabled(Output.of(natTranslationEnabled));
        }

        /**
         * @param oracleCanInitiate Indicates whether Oracle can only respond to a request to start an IPSec tunnel from the CPE device (`RESPONDER_ONLY`), or both respond to and initiate requests (`INITIATOR_OR_RESPONDER`).
         * 
         * @return builder
         * 
         */
        public Builder oracleCanInitiate(@Nullable Output<String> oracleCanInitiate) {
            $.oracleCanInitiate = oracleCanInitiate;
            return this;
        }

        /**
         * @param oracleCanInitiate Indicates whether Oracle can only respond to a request to start an IPSec tunnel from the CPE device (`RESPONDER_ONLY`), or both respond to and initiate requests (`INITIATOR_OR_RESPONDER`).
         * 
         * @return builder
         * 
         */
        public Builder oracleCanInitiate(String oracleCanInitiate) {
            return oracleCanInitiate(Output.of(oracleCanInitiate));
        }

        /**
         * @param phaseOneDetails Configuration details for IKE phase one (ISAKMP) configuration parameters.
         * 
         * See [PhaseOneConfigDetails](https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/datatypes/PhaseOneConfigDetails) for allowed values but note naming scheme follows [TunnelPhaseOneDetails](https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/datatypes/TunnelPhaseOneDetails).
         * 
         * @return builder
         * 
         */
        public Builder phaseOneDetails(@Nullable Output<IpsecConnectionTunnelManagementPhaseOneDetailsArgs> phaseOneDetails) {
            $.phaseOneDetails = phaseOneDetails;
            return this;
        }

        /**
         * @param phaseOneDetails Configuration details for IKE phase one (ISAKMP) configuration parameters.
         * 
         * See [PhaseOneConfigDetails](https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/datatypes/PhaseOneConfigDetails) for allowed values but note naming scheme follows [TunnelPhaseOneDetails](https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/datatypes/TunnelPhaseOneDetails).
         * 
         * @return builder
         * 
         */
        public Builder phaseOneDetails(IpsecConnectionTunnelManagementPhaseOneDetailsArgs phaseOneDetails) {
            return phaseOneDetails(Output.of(phaseOneDetails));
        }

        /**
         * @param phaseTwoDetails Configuration details for IPSec phase two configuration parameters.
         * 
         * See [PhaseTwoConfigDetails](https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/datatypes/PhaseTwoConfigDetails) for allowed values, but note naming scheme follows [TunnelPhaseTwoDetails](https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/datatypes/TunnelPhaseTwoDetails).
         * 
         * @return builder
         * 
         */
        public Builder phaseTwoDetails(@Nullable Output<IpsecConnectionTunnelManagementPhaseTwoDetailsArgs> phaseTwoDetails) {
            $.phaseTwoDetails = phaseTwoDetails;
            return this;
        }

        /**
         * @param phaseTwoDetails Configuration details for IPSec phase two configuration parameters.
         * 
         * See [PhaseTwoConfigDetails](https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/datatypes/PhaseTwoConfigDetails) for allowed values, but note naming scheme follows [TunnelPhaseTwoDetails](https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/datatypes/TunnelPhaseTwoDetails).
         * 
         * @return builder
         * 
         */
        public Builder phaseTwoDetails(IpsecConnectionTunnelManagementPhaseTwoDetailsArgs phaseTwoDetails) {
            return phaseTwoDetails(Output.of(phaseTwoDetails));
        }

        /**
         * @param routing The type of routing to use for this tunnel (either BGP dynamic routing, STATIC routing or POLICY routing).
         * 
         * @return builder
         * 
         */
        public Builder routing(@Nullable Output<String> routing) {
            $.routing = routing;
            return this;
        }

        /**
         * @param routing The type of routing to use for this tunnel (either BGP dynamic routing, STATIC routing or POLICY routing).
         * 
         * @return builder
         * 
         */
        public Builder routing(String routing) {
            return routing(Output.of(routing));
        }

        /**
         * @param sharedSecret The shared secret (pre-shared key) to use for the IPSec tunnel. If you don&#39;t provide a value, Oracle generates a value for you. You can specify your own shared secret later if you like with [UpdateIPSecConnectionTunnelSharedSecret](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/IPSecConnectionTunnelSharedSecret/UpdateIPSecConnectionTunnelSharedSecret).  Example: `EXAMPLEToUis6j1c.p8G.dVQxcmdfMO0yXMLi.lZTbYCMDGu4V8o`
         * 
         * @return builder
         * 
         */
        public Builder sharedSecret(@Nullable Output<String> sharedSecret) {
            $.sharedSecret = sharedSecret;
            return this;
        }

        /**
         * @param sharedSecret The shared secret (pre-shared key) to use for the IPSec tunnel. If you don&#39;t provide a value, Oracle generates a value for you. You can specify your own shared secret later if you like with [UpdateIPSecConnectionTunnelSharedSecret](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/IPSecConnectionTunnelSharedSecret/UpdateIPSecConnectionTunnelSharedSecret).  Example: `EXAMPLEToUis6j1c.p8G.dVQxcmdfMO0yXMLi.lZTbYCMDGu4V8o`
         * 
         * @return builder
         * 
         */
        public Builder sharedSecret(String sharedSecret) {
            return sharedSecret(Output.of(sharedSecret));
        }

        /**
         * @param state The IPSec connection&#39;s tunnel&#39;s lifecycle state.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The IPSec connection&#39;s tunnel&#39;s lifecycle state.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param status The tunnel&#39;s current state.
         * 
         * @return builder
         * 
         */
        public Builder status(@Nullable Output<String> status) {
            $.status = status;
            return this;
        }

        /**
         * @param status The tunnel&#39;s current state.
         * 
         * @return builder
         * 
         */
        public Builder status(String status) {
            return status(Output.of(status));
        }

        /**
         * @param timeCreated The date and time the IPSec connection tunnel was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time the IPSec connection tunnel was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeStatusUpdated When the status of the tunnel last changed, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeStatusUpdated(@Nullable Output<String> timeStatusUpdated) {
            $.timeStatusUpdated = timeStatusUpdated;
            return this;
        }

        /**
         * @param timeStatusUpdated When the status of the tunnel last changed, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeStatusUpdated(String timeStatusUpdated) {
            return timeStatusUpdated(Output.of(timeStatusUpdated));
        }

        /**
         * @param tunnelId The OCID of the IPSec connection&#39;s tunnel.
         * 
         * @return builder
         * 
         */
        public Builder tunnelId(@Nullable Output<String> tunnelId) {
            $.tunnelId = tunnelId;
            return this;
        }

        /**
         * @param tunnelId The OCID of the IPSec connection&#39;s tunnel.
         * 
         * @return builder
         * 
         */
        public Builder tunnelId(String tunnelId) {
            return tunnelId(Output.of(tunnelId));
        }

        /**
         * @param vpnIp The IP address of Oracle&#39;s VPN headend.  Example: `129.146.17.50`
         * 
         * @return builder
         * 
         */
        public Builder vpnIp(@Nullable Output<String> vpnIp) {
            $.vpnIp = vpnIp;
            return this;
        }

        /**
         * @param vpnIp The IP address of Oracle&#39;s VPN headend.  Example: `129.146.17.50`
         * 
         * @return builder
         * 
         */
        public Builder vpnIp(String vpnIp) {
            return vpnIp(Output.of(vpnIp));
        }

        public IpsecConnectionTunnelManagementState build() {
            return $;
        }
    }

}
