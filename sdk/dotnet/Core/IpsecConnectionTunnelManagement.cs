// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    /// <summary>
    /// This resource provides the Ip Sec Connection Tunnel Management resource in Oracle Cloud Infrastructure Core service.
    /// 
    /// Updates the specified tunnel. This operation lets you change tunnel attributes such as the
    /// routing type (BGP dynamic routing or static routing). Here are some important notes:
    /// 
    ///     * If you change the tunnel's routing type or BGP session configuration, the tunnel will go
    ///     down while it's reprovisioned.
    ///     
    ///     * If you want to switch the tunnel's `routing` from `STATIC` to `BGP`, make sure the tunnel's
    ///     BGP session configuration attributes have been set (bgpSessionConfig).
    ///     
    ///     * If you want to switch the tunnel's `routing` from `BGP` to `STATIC`, make sure the
    ///     IPSecConnection already has at least one valid CIDR
    ///     static route.
    /// 
    /// ** IMPORTANT **
    /// Destroying `the oci.Core.IpsecConnectionTunnelManagement` leaves the resource in its existing state. It will not destroy the tunnel and it will not return the tunnel to its default values.
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// class MyStack : Stack
    /// {
    ///     public MyStack()
    ///     {
    ///         var testIpSecConnectionTunnel = new Oci.Core.IpsecConnectionTunnelManagement("testIpSecConnectionTunnel", new Oci.Core.IpsecConnectionTunnelManagementArgs
    ///         {
    ///             IpsecId = oci_core_ipsec.Test_ipsec.Id,
    ///             TunnelId = data.Oci_core_ipsec_connection_tunnels.Test_ip_sec_connection_tunnels.Ip_sec_connection_tunnels[0].Id,
    ///             Routing = @var.Ip_sec_connection_tunnel_management_routing,
    ///             BgpSessionInfos = 
    ///             {
    ///                 new Oci.Core.Inputs.IpsecConnectionTunnelManagementBgpSessionInfoArgs
    ///                 {
    ///                     CustomerBgpAsn = @var.Ip_sec_connection_tunnel_management_bgp_session_info_customer_bgp_asn,
    ///                     CustomerInterfaceIp = @var.Ip_sec_connection_tunnel_management_bgp_session_info_customer_interface_ip,
    ///                     OracleInterfaceIp = @var.Ip_sec_connection_tunnel_management_bgp_session_info_oracle_interface_ip,
    ///                 },
    ///             },
    ///             DisplayName = @var.Ip_sec_connection_tunnel_management_display_name,
    ///             EncryptionDomainConfig = new Oci.Core.Inputs.IpsecConnectionTunnelManagementEncryptionDomainConfigArgs
    ///             {
    ///                 CpeTrafficSelectors = @var.Ip_sec_connection_tunnel_management_encryption_domain_config_cpe_traffic_selector,
    ///                 OracleTrafficSelectors = @var.Ip_sec_connection_tunnel_management_encryption_domain_config_oracle_traffic_selector,
    ///             },
    ///             SharedSecret = @var.Ip_sec_connection_tunnel_management_shared_secret,
    ///             IkeVersion = "V1",
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// </summary>
    [OciResourceType("oci:Core/ipsecConnectionTunnelManagement:IpsecConnectionTunnelManagement")]
    public partial class IpsecConnectionTunnelManagement : Pulumi.CustomResource
    {
        /// <summary>
        /// Information for establishing a BGP session for the IPSec tunnel. Required if the tunnel uses BGP dynamic routing.
        /// </summary>
        [Output("bgpSessionInfos")]
        public Output<ImmutableArray<Outputs.IpsecConnectionTunnelManagementBgpSessionInfo>> BgpSessionInfos { get; private set; } = null!;

        /// <summary>
        /// The OCID of the compartment containing the tunnel.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// The IP address of Cpe headend.  Example: `129.146.17.50`
        /// </summary>
        [Output("cpeIp")]
        public Output<string> CpeIp { get; private set; } = null!;

        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        [Output("dpdMode")]
        public Output<string> DpdMode { get; private set; } = null!;

        [Output("dpdTimeoutInSec")]
        public Output<int> DpdTimeoutInSec { get; private set; } = null!;

        /// <summary>
        /// Configuration information used by the encryption domain policy. Required if the tunnel uses POLICY routing.
        /// </summary>
        [Output("encryptionDomainConfig")]
        public Output<Outputs.IpsecConnectionTunnelManagementEncryptionDomainConfig> EncryptionDomainConfig { get; private set; } = null!;

        /// <summary>
        /// Internet Key Exchange protocol version.
        /// </summary>
        [Output("ikeVersion")]
        public Output<string> IkeVersion { get; private set; } = null!;

        /// <summary>
        /// The OCID of the IPSec connection.
        /// </summary>
        [Output("ipsecId")]
        public Output<string> IpsecId { get; private set; } = null!;

        [Output("natTranslationEnabled")]
        public Output<string> NatTranslationEnabled { get; private set; } = null!;

        [Output("oracleCanInitiate")]
        public Output<string> OracleCanInitiate { get; private set; } = null!;

        [Output("phaseOneDetails")]
        public Output<ImmutableArray<Outputs.IpsecConnectionTunnelManagementPhaseOneDetail>> PhaseOneDetails { get; private set; } = null!;

        [Output("phaseTwoDetails")]
        public Output<ImmutableArray<Outputs.IpsecConnectionTunnelManagementPhaseTwoDetail>> PhaseTwoDetails { get; private set; } = null!;

        /// <summary>
        /// The type of routing to use for this tunnel (either BGP dynamic routing, STATIC routing or POLICY routing).
        /// </summary>
        [Output("routing")]
        public Output<string> Routing { get; private set; } = null!;

        /// <summary>
        /// The shared secret (pre-shared key) to use for the IPSec tunnel. If you don't provide a value, Oracle generates a value for you. You can specify your own shared secret later if you like with [UpdateIPSecConnectionTunnelSharedSecret](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/IPSecConnectionTunnelSharedSecret/UpdateIPSecConnectionTunnelSharedSecret).  Example: `EXAMPLEToUis6j1c.p8G.dVQxcmdfMO0yXMLi.lZTbYCMDGu4V8o`
        /// </summary>
        [Output("sharedSecret")]
        public Output<string> SharedSecret { get; private set; } = null!;

        /// <summary>
        /// The IPSec connection's tunnel's lifecycle state.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// The tunnel's current state.
        /// </summary>
        [Output("status")]
        public Output<string> Status { get; private set; } = null!;

        /// <summary>
        /// The date and time the IPSec connection tunnel was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// When the status of the tunnel last changed, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Output("timeStatusUpdated")]
        public Output<string> TimeStatusUpdated { get; private set; } = null!;

        /// <summary>
        /// The OCID of the IPSec connection's tunnel.
        /// </summary>
        [Output("tunnelId")]
        public Output<string> TunnelId { get; private set; } = null!;

        /// <summary>
        /// The IP address of Oracle's VPN headend.  Example: `129.146.17.50`
        /// </summary>
        [Output("vpnIp")]
        public Output<string> VpnIp { get; private set; } = null!;


        /// <summary>
        /// Create a IpsecConnectionTunnelManagement resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public IpsecConnectionTunnelManagement(string name, IpsecConnectionTunnelManagementArgs args, CustomResourceOptions? options = null)
            : base("oci:Core/ipsecConnectionTunnelManagement:IpsecConnectionTunnelManagement", name, args ?? new IpsecConnectionTunnelManagementArgs(), MakeResourceOptions(options, ""))
        {
        }

        private IpsecConnectionTunnelManagement(string name, Input<string> id, IpsecConnectionTunnelManagementState? state = null, CustomResourceOptions? options = null)
            : base("oci:Core/ipsecConnectionTunnelManagement:IpsecConnectionTunnelManagement", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing IpsecConnectionTunnelManagement resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static IpsecConnectionTunnelManagement Get(string name, Input<string> id, IpsecConnectionTunnelManagementState? state = null, CustomResourceOptions? options = null)
        {
            return new IpsecConnectionTunnelManagement(name, id, state, options);
        }
    }

    public sealed class IpsecConnectionTunnelManagementArgs : Pulumi.ResourceArgs
    {
        [Input("bgpSessionInfos")]
        private InputList<Inputs.IpsecConnectionTunnelManagementBgpSessionInfoArgs>? _bgpSessionInfos;

        /// <summary>
        /// Information for establishing a BGP session for the IPSec tunnel. Required if the tunnel uses BGP dynamic routing.
        /// </summary>
        public InputList<Inputs.IpsecConnectionTunnelManagementBgpSessionInfoArgs> BgpSessionInfos
        {
            get => _bgpSessionInfos ?? (_bgpSessionInfos = new InputList<Inputs.IpsecConnectionTunnelManagementBgpSessionInfoArgs>());
            set => _bgpSessionInfos = value;
        }

        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// Configuration information used by the encryption domain policy. Required if the tunnel uses POLICY routing.
        /// </summary>
        [Input("encryptionDomainConfig")]
        public Input<Inputs.IpsecConnectionTunnelManagementEncryptionDomainConfigArgs>? EncryptionDomainConfig { get; set; }

        /// <summary>
        /// Internet Key Exchange protocol version.
        /// </summary>
        [Input("ikeVersion")]
        public Input<string>? IkeVersion { get; set; }

        /// <summary>
        /// The OCID of the IPSec connection.
        /// </summary>
        [Input("ipsecId", required: true)]
        public Input<string> IpsecId { get; set; } = null!;

        /// <summary>
        /// The type of routing to use for this tunnel (either BGP dynamic routing, STATIC routing or POLICY routing).
        /// </summary>
        [Input("routing", required: true)]
        public Input<string> Routing { get; set; } = null!;

        /// <summary>
        /// The shared secret (pre-shared key) to use for the IPSec tunnel. If you don't provide a value, Oracle generates a value for you. You can specify your own shared secret later if you like with [UpdateIPSecConnectionTunnelSharedSecret](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/IPSecConnectionTunnelSharedSecret/UpdateIPSecConnectionTunnelSharedSecret).  Example: `EXAMPLEToUis6j1c.p8G.dVQxcmdfMO0yXMLi.lZTbYCMDGu4V8o`
        /// </summary>
        [Input("sharedSecret")]
        public Input<string>? SharedSecret { get; set; }

        /// <summary>
        /// The OCID of the IPSec connection's tunnel.
        /// </summary>
        [Input("tunnelId", required: true)]
        public Input<string> TunnelId { get; set; } = null!;

        public IpsecConnectionTunnelManagementArgs()
        {
        }
    }

    public sealed class IpsecConnectionTunnelManagementState : Pulumi.ResourceArgs
    {
        [Input("bgpSessionInfos")]
        private InputList<Inputs.IpsecConnectionTunnelManagementBgpSessionInfoGetArgs>? _bgpSessionInfos;

        /// <summary>
        /// Information for establishing a BGP session for the IPSec tunnel. Required if the tunnel uses BGP dynamic routing.
        /// </summary>
        public InputList<Inputs.IpsecConnectionTunnelManagementBgpSessionInfoGetArgs> BgpSessionInfos
        {
            get => _bgpSessionInfos ?? (_bgpSessionInfos = new InputList<Inputs.IpsecConnectionTunnelManagementBgpSessionInfoGetArgs>());
            set => _bgpSessionInfos = value;
        }

        /// <summary>
        /// The OCID of the compartment containing the tunnel.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// The IP address of Cpe headend.  Example: `129.146.17.50`
        /// </summary>
        [Input("cpeIp")]
        public Input<string>? CpeIp { get; set; }

        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("dpdMode")]
        public Input<string>? DpdMode { get; set; }

        [Input("dpdTimeoutInSec")]
        public Input<int>? DpdTimeoutInSec { get; set; }

        /// <summary>
        /// Configuration information used by the encryption domain policy. Required if the tunnel uses POLICY routing.
        /// </summary>
        [Input("encryptionDomainConfig")]
        public Input<Inputs.IpsecConnectionTunnelManagementEncryptionDomainConfigGetArgs>? EncryptionDomainConfig { get; set; }

        /// <summary>
        /// Internet Key Exchange protocol version.
        /// </summary>
        [Input("ikeVersion")]
        public Input<string>? IkeVersion { get; set; }

        /// <summary>
        /// The OCID of the IPSec connection.
        /// </summary>
        [Input("ipsecId")]
        public Input<string>? IpsecId { get; set; }

        [Input("natTranslationEnabled")]
        public Input<string>? NatTranslationEnabled { get; set; }

        [Input("oracleCanInitiate")]
        public Input<string>? OracleCanInitiate { get; set; }

        [Input("phaseOneDetails")]
        private InputList<Inputs.IpsecConnectionTunnelManagementPhaseOneDetailGetArgs>? _phaseOneDetails;
        public InputList<Inputs.IpsecConnectionTunnelManagementPhaseOneDetailGetArgs> PhaseOneDetails
        {
            get => _phaseOneDetails ?? (_phaseOneDetails = new InputList<Inputs.IpsecConnectionTunnelManagementPhaseOneDetailGetArgs>());
            set => _phaseOneDetails = value;
        }

        [Input("phaseTwoDetails")]
        private InputList<Inputs.IpsecConnectionTunnelManagementPhaseTwoDetailGetArgs>? _phaseTwoDetails;
        public InputList<Inputs.IpsecConnectionTunnelManagementPhaseTwoDetailGetArgs> PhaseTwoDetails
        {
            get => _phaseTwoDetails ?? (_phaseTwoDetails = new InputList<Inputs.IpsecConnectionTunnelManagementPhaseTwoDetailGetArgs>());
            set => _phaseTwoDetails = value;
        }

        /// <summary>
        /// The type of routing to use for this tunnel (either BGP dynamic routing, STATIC routing or POLICY routing).
        /// </summary>
        [Input("routing")]
        public Input<string>? Routing { get; set; }

        /// <summary>
        /// The shared secret (pre-shared key) to use for the IPSec tunnel. If you don't provide a value, Oracle generates a value for you. You can specify your own shared secret later if you like with [UpdateIPSecConnectionTunnelSharedSecret](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/IPSecConnectionTunnelSharedSecret/UpdateIPSecConnectionTunnelSharedSecret).  Example: `EXAMPLEToUis6j1c.p8G.dVQxcmdfMO0yXMLi.lZTbYCMDGu4V8o`
        /// </summary>
        [Input("sharedSecret")]
        public Input<string>? SharedSecret { get; set; }

        /// <summary>
        /// The IPSec connection's tunnel's lifecycle state.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The tunnel's current state.
        /// </summary>
        [Input("status")]
        public Input<string>? Status { get; set; }

        /// <summary>
        /// The date and time the IPSec connection tunnel was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// When the status of the tunnel last changed, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Input("timeStatusUpdated")]
        public Input<string>? TimeStatusUpdated { get; set; }

        /// <summary>
        /// The OCID of the IPSec connection's tunnel.
        /// </summary>
        [Input("tunnelId")]
        public Input<string>? TunnelId { get; set; }

        /// <summary>
        /// The IP address of Oracle's VPN headend.  Example: `129.146.17.50`
        /// </summary>
        [Input("vpnIp")]
        public Input<string>? VpnIp { get; set; }

        public IpsecConnectionTunnelManagementState()
        {
        }
    }
}
