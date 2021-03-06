// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Core.IpsecConnectionTunnelManagementArgs;
import com.pulumi.oci.Core.inputs.IpsecConnectionTunnelManagementState;
import com.pulumi.oci.Core.outputs.IpsecConnectionTunnelManagementBgpSessionInfo;
import com.pulumi.oci.Core.outputs.IpsecConnectionTunnelManagementEncryptionDomainConfig;
import com.pulumi.oci.Core.outputs.IpsecConnectionTunnelManagementPhaseOneDetail;
import com.pulumi.oci.Core.outputs.IpsecConnectionTunnelManagementPhaseTwoDetail;
import com.pulumi.oci.Utilities;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import javax.annotation.Nullable;

/**
 * This resource provides the Ip Sec Connection Tunnel Management resource in Oracle Cloud Infrastructure Core service.
 * 
 * Updates the specified tunnel. This operation lets you change tunnel attributes such as the
 * routing type (BGP dynamic routing or static routing). Here are some important notes:
 * 
 *     * If you change the tunnel&#39;s routing type or BGP session configuration, the tunnel will go
 *     down while it&#39;s reprovisioned.
 *     
 *     * If you want to switch the tunnel&#39;s `routing` from `STATIC` to `BGP`, make sure the tunnel&#39;s
 *     BGP session configuration attributes have been set (bgpSessionConfig).
 *     
 *     * If you want to switch the tunnel&#39;s `routing` from `BGP` to `STATIC`, make sure the
 *     IPSecConnection already has at least one valid CIDR
 *     static route.
 * 
 * ** IMPORTANT **
 * Destroying `the oci.Core.IpsecConnectionTunnelManagement` leaves the resource in its existing state. It will not destroy the tunnel and it will not return the tunnel to its default values.
 * 
 * ## Example Usage
 * 
 */
@ResourceType(type="oci:Core/ipsecConnectionTunnelManagement:IpsecConnectionTunnelManagement")
public class IpsecConnectionTunnelManagement extends com.pulumi.resources.CustomResource {
    /**
     * Information for establishing a BGP session for the IPSec tunnel. Required if the tunnel uses BGP dynamic routing.
     * 
     */
    @Export(name="bgpSessionInfos", type=List.class, parameters={IpsecConnectionTunnelManagementBgpSessionInfo.class})
    private Output<List<IpsecConnectionTunnelManagementBgpSessionInfo>> bgpSessionInfos;

    /**
     * @return Information for establishing a BGP session for the IPSec tunnel. Required if the tunnel uses BGP dynamic routing.
     * 
     */
    public Output<List<IpsecConnectionTunnelManagementBgpSessionInfo>> bgpSessionInfos() {
        return this.bgpSessionInfos;
    }
    /**
     * The OCID of the compartment containing the tunnel.
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return The OCID of the compartment containing the tunnel.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * The IP address of Cpe headend.  Example: `129.146.17.50`
     * 
     */
    @Export(name="cpeIp", type=String.class, parameters={})
    private Output<String> cpeIp;

    /**
     * @return The IP address of Cpe headend.  Example: `129.146.17.50`
     * 
     */
    public Output<String> cpeIp() {
        return this.cpeIp;
    }
    /**
     * A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    @Export(name="dpdMode", type=String.class, parameters={})
    private Output<String> dpdMode;

    public Output<String> dpdMode() {
        return this.dpdMode;
    }
    @Export(name="dpdTimeoutInSec", type=Integer.class, parameters={})
    private Output<Integer> dpdTimeoutInSec;

    public Output<Integer> dpdTimeoutInSec() {
        return this.dpdTimeoutInSec;
    }
    /**
     * Configuration information used by the encryption domain policy. Required if the tunnel uses POLICY routing.
     * 
     */
    @Export(name="encryptionDomainConfig", type=IpsecConnectionTunnelManagementEncryptionDomainConfig.class, parameters={})
    private Output<IpsecConnectionTunnelManagementEncryptionDomainConfig> encryptionDomainConfig;

    /**
     * @return Configuration information used by the encryption domain policy. Required if the tunnel uses POLICY routing.
     * 
     */
    public Output<IpsecConnectionTunnelManagementEncryptionDomainConfig> encryptionDomainConfig() {
        return this.encryptionDomainConfig;
    }
    /**
     * Internet Key Exchange protocol version.
     * 
     */
    @Export(name="ikeVersion", type=String.class, parameters={})
    private Output<String> ikeVersion;

    /**
     * @return Internet Key Exchange protocol version.
     * 
     */
    public Output<String> ikeVersion() {
        return this.ikeVersion;
    }
    /**
     * The OCID of the IPSec connection.
     * 
     */
    @Export(name="ipsecId", type=String.class, parameters={})
    private Output<String> ipsecId;

    /**
     * @return The OCID of the IPSec connection.
     * 
     */
    public Output<String> ipsecId() {
        return this.ipsecId;
    }
    @Export(name="natTranslationEnabled", type=String.class, parameters={})
    private Output<String> natTranslationEnabled;

    public Output<String> natTranslationEnabled() {
        return this.natTranslationEnabled;
    }
    @Export(name="oracleCanInitiate", type=String.class, parameters={})
    private Output<String> oracleCanInitiate;

    public Output<String> oracleCanInitiate() {
        return this.oracleCanInitiate;
    }
    @Export(name="phaseOneDetails", type=List.class, parameters={IpsecConnectionTunnelManagementPhaseOneDetail.class})
    private Output<List<IpsecConnectionTunnelManagementPhaseOneDetail>> phaseOneDetails;

    public Output<List<IpsecConnectionTunnelManagementPhaseOneDetail>> phaseOneDetails() {
        return this.phaseOneDetails;
    }
    @Export(name="phaseTwoDetails", type=List.class, parameters={IpsecConnectionTunnelManagementPhaseTwoDetail.class})
    private Output<List<IpsecConnectionTunnelManagementPhaseTwoDetail>> phaseTwoDetails;

    public Output<List<IpsecConnectionTunnelManagementPhaseTwoDetail>> phaseTwoDetails() {
        return this.phaseTwoDetails;
    }
    /**
     * The type of routing to use for this tunnel (either BGP dynamic routing, STATIC routing or POLICY routing).
     * 
     */
    @Export(name="routing", type=String.class, parameters={})
    private Output<String> routing;

    /**
     * @return The type of routing to use for this tunnel (either BGP dynamic routing, STATIC routing or POLICY routing).
     * 
     */
    public Output<String> routing() {
        return this.routing;
    }
    /**
     * The shared secret (pre-shared key) to use for the IPSec tunnel. If you don&#39;t provide a value, Oracle generates a value for you. You can specify your own shared secret later if you like with [UpdateIPSecConnectionTunnelSharedSecret](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/IPSecConnectionTunnelSharedSecret/UpdateIPSecConnectionTunnelSharedSecret).  Example: `EXAMPLEToUis6j1c.p8G.dVQxcmdfMO0yXMLi.lZTbYCMDGu4V8o`
     * 
     */
    @Export(name="sharedSecret", type=String.class, parameters={})
    private Output<String> sharedSecret;

    /**
     * @return The shared secret (pre-shared key) to use for the IPSec tunnel. If you don&#39;t provide a value, Oracle generates a value for you. You can specify your own shared secret later if you like with [UpdateIPSecConnectionTunnelSharedSecret](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/IPSecConnectionTunnelSharedSecret/UpdateIPSecConnectionTunnelSharedSecret).  Example: `EXAMPLEToUis6j1c.p8G.dVQxcmdfMO0yXMLi.lZTbYCMDGu4V8o`
     * 
     */
    public Output<String> sharedSecret() {
        return this.sharedSecret;
    }
    /**
     * The IPSec connection&#39;s tunnel&#39;s lifecycle state.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The IPSec connection&#39;s tunnel&#39;s lifecycle state.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The tunnel&#39;s current state.
     * 
     */
    @Export(name="status", type=String.class, parameters={})
    private Output<String> status;

    /**
     * @return The tunnel&#39;s current state.
     * 
     */
    public Output<String> status() {
        return this.status;
    }
    /**
     * The date and time the IPSec connection tunnel was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The date and time the IPSec connection tunnel was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * When the status of the tunnel last changed, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Export(name="timeStatusUpdated", type=String.class, parameters={})
    private Output<String> timeStatusUpdated;

    /**
     * @return When the status of the tunnel last changed, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Output<String> timeStatusUpdated() {
        return this.timeStatusUpdated;
    }
    /**
     * The OCID of the IPSec connection&#39;s tunnel.
     * 
     */
    @Export(name="tunnelId", type=String.class, parameters={})
    private Output<String> tunnelId;

    /**
     * @return The OCID of the IPSec connection&#39;s tunnel.
     * 
     */
    public Output<String> tunnelId() {
        return this.tunnelId;
    }
    /**
     * The IP address of Oracle&#39;s VPN headend.  Example: `129.146.17.50`
     * 
     */
    @Export(name="vpnIp", type=String.class, parameters={})
    private Output<String> vpnIp;

    /**
     * @return The IP address of Oracle&#39;s VPN headend.  Example: `129.146.17.50`
     * 
     */
    public Output<String> vpnIp() {
        return this.vpnIp;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public IpsecConnectionTunnelManagement(String name) {
        this(name, IpsecConnectionTunnelManagementArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public IpsecConnectionTunnelManagement(String name, IpsecConnectionTunnelManagementArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public IpsecConnectionTunnelManagement(String name, IpsecConnectionTunnelManagementArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Core/ipsecConnectionTunnelManagement:IpsecConnectionTunnelManagement", name, args == null ? IpsecConnectionTunnelManagementArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private IpsecConnectionTunnelManagement(String name, Output<String> id, @Nullable IpsecConnectionTunnelManagementState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Core/ipsecConnectionTunnelManagement:IpsecConnectionTunnelManagement", name, state, makeResourceOptions(options, id));
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<String> id) {
        var defaultOptions = com.pulumi.resources.CustomResourceOptions.builder()
            .version(Utilities.getVersion())
            .build();
        return com.pulumi.resources.CustomResourceOptions.merge(defaultOptions, options, id);
    }

    /**
     * Get an existing Host resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state
     * @param options Optional settings to control the behavior of the CustomResource.
     */
    public static IpsecConnectionTunnelManagement get(String name, Output<String> id, @Nullable IpsecConnectionTunnelManagementState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new IpsecConnectionTunnelManagement(name, id, state, options);
    }
}
