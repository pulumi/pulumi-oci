// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetVmClusterRecommendedNetwork
    {
        /// <summary>
        /// This data source provides details about a specific Vm Cluster Recommended Network resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Generates a recommended Cloud@Customer VM cluster network configuration.
        /// </summary>
        public static Task<GetVmClusterRecommendedNetworkResult> InvokeAsync(GetVmClusterRecommendedNetworkArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetVmClusterRecommendedNetworkResult>("oci:Database/getVmClusterRecommendedNetwork:getVmClusterRecommendedNetwork", args ?? new GetVmClusterRecommendedNetworkArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Vm Cluster Recommended Network resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Generates a recommended Cloud@Customer VM cluster network configuration.
        /// </summary>
        public static Output<GetVmClusterRecommendedNetworkResult> Invoke(GetVmClusterRecommendedNetworkInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetVmClusterRecommendedNetworkResult>("oci:Database/getVmClusterRecommendedNetwork:getVmClusterRecommendedNetwork", args ?? new GetVmClusterRecommendedNetworkInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetVmClusterRecommendedNetworkArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private Dictionary<string, object>? _definedTags;

        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public Dictionary<string, object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new Dictionary<string, object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// The user-friendly name for the VM cluster network. The name does not need to be unique.
        /// </summary>
        [Input("displayName", required: true)]
        public string DisplayName { get; set; } = null!;

        [Input("dns")]
        private List<string>? _dns;

        /// <summary>
        /// The list of DNS server IP addresses. Maximum of 3 allowed.
        /// </summary>
        public List<string> Dns
        {
            get => _dns ?? (_dns = new List<string>());
            set => _dns = value;
        }

        /// <summary>
        /// The Exadata infrastructure [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("exadataInfrastructureId", required: true)]
        public string ExadataInfrastructureId { get; set; } = null!;

        [Input("freeformTags")]
        private Dictionary<string, object>? _freeformTags;

        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public Dictionary<string, object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new Dictionary<string, object>());
            set => _freeformTags = value;
        }

        [Input("networks", required: true)]
        private List<Inputs.GetVmClusterRecommendedNetworkNetworkArgs>? _networks;

        /// <summary>
        /// List of parameters for generation of the client and backup networks.
        /// </summary>
        public List<Inputs.GetVmClusterRecommendedNetworkNetworkArgs> Networks
        {
            get => _networks ?? (_networks = new List<Inputs.GetVmClusterRecommendedNetworkNetworkArgs>());
            set => _networks = value;
        }

        [Input("ntps")]
        private List<string>? _ntps;

        /// <summary>
        /// The list of NTP server IP addresses. Maximum of 3 allowed.
        /// </summary>
        public List<string> Ntps
        {
            get => _ntps ?? (_ntps = new List<string>());
            set => _ntps = value;
        }

        /// <summary>
        /// The SCAN TCPIP port. Default is 1521.
        /// </summary>
        [Input("scanListenerPortTcp")]
        public int? ScanListenerPortTcp { get; set; }

        /// <summary>
        /// The SCAN TCPIP SSL port. Default is 2484.
        /// </summary>
        [Input("scanListenerPortTcpSsl")]
        public int? ScanListenerPortTcpSsl { get; set; }

        public GetVmClusterRecommendedNetworkArgs()
        {
        }
        public static new GetVmClusterRecommendedNetworkArgs Empty => new GetVmClusterRecommendedNetworkArgs();
    }

    public sealed class GetVmClusterRecommendedNetworkInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// The user-friendly name for the VM cluster network. The name does not need to be unique.
        /// </summary>
        [Input("displayName", required: true)]
        public Input<string> DisplayName { get; set; } = null!;

        [Input("dns")]
        private InputList<string>? _dns;

        /// <summary>
        /// The list of DNS server IP addresses. Maximum of 3 allowed.
        /// </summary>
        public InputList<string> Dns
        {
            get => _dns ?? (_dns = new InputList<string>());
            set => _dns = value;
        }

        /// <summary>
        /// The Exadata infrastructure [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("exadataInfrastructureId", required: true)]
        public Input<string> ExadataInfrastructureId { get; set; } = null!;

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        [Input("networks", required: true)]
        private InputList<Inputs.GetVmClusterRecommendedNetworkNetworkInputArgs>? _networks;

        /// <summary>
        /// List of parameters for generation of the client and backup networks.
        /// </summary>
        public InputList<Inputs.GetVmClusterRecommendedNetworkNetworkInputArgs> Networks
        {
            get => _networks ?? (_networks = new InputList<Inputs.GetVmClusterRecommendedNetworkNetworkInputArgs>());
            set => _networks = value;
        }

        [Input("ntps")]
        private InputList<string>? _ntps;

        /// <summary>
        /// The list of NTP server IP addresses. Maximum of 3 allowed.
        /// </summary>
        public InputList<string> Ntps
        {
            get => _ntps ?? (_ntps = new InputList<string>());
            set => _ntps = value;
        }

        /// <summary>
        /// The SCAN TCPIP port. Default is 1521.
        /// </summary>
        [Input("scanListenerPortTcp")]
        public Input<int>? ScanListenerPortTcp { get; set; }

        /// <summary>
        /// The SCAN TCPIP SSL port. Default is 2484.
        /// </summary>
        [Input("scanListenerPortTcpSsl")]
        public Input<int>? ScanListenerPortTcpSsl { get; set; }

        public GetVmClusterRecommendedNetworkInvokeArgs()
        {
        }
        public static new GetVmClusterRecommendedNetworkInvokeArgs Empty => new GetVmClusterRecommendedNetworkInvokeArgs();
    }


    [OutputType]
    public sealed class GetVmClusterRecommendedNetworkResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// The user-friendly name for the Exadata Cloud@Customer VM cluster network. The name does not need to be unique.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The list of DNS server IP addresses. Maximum of 3 allowed.
        /// </summary>
        public readonly ImmutableArray<string> Dns;
        public readonly string ExadataInfrastructureId;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly ImmutableArray<Outputs.GetVmClusterRecommendedNetworkNetworkResult> Networks;
        /// <summary>
        /// The list of NTP server IP addresses. Maximum of 3 allowed.
        /// </summary>
        public readonly ImmutableArray<string> Ntps;
        /// <summary>
        /// The SCAN TCPIP port. Default is 1521.
        /// </summary>
        public readonly int? ScanListenerPortTcp;
        /// <summary>
        /// The SCAN TCPIP SSL port. Default is 2484.
        /// </summary>
        public readonly int? ScanListenerPortTcpSsl;
        /// <summary>
        /// The SCAN details.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetVmClusterRecommendedNetworkScanResult> Scans;
        /// <summary>
        /// Details of the client and backup networks.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetVmClusterRecommendedNetworkVmNetworkResult> VmNetworks;

        [OutputConstructor]
        private GetVmClusterRecommendedNetworkResult(
            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string displayName,

            ImmutableArray<string> dns,

            string exadataInfrastructureId,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            ImmutableArray<Outputs.GetVmClusterRecommendedNetworkNetworkResult> networks,

            ImmutableArray<string> ntps,

            int? scanListenerPortTcp,

            int? scanListenerPortTcpSsl,

            ImmutableArray<Outputs.GetVmClusterRecommendedNetworkScanResult> scans,

            ImmutableArray<Outputs.GetVmClusterRecommendedNetworkVmNetworkResult> vmNetworks)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            Dns = dns;
            ExadataInfrastructureId = exadataInfrastructureId;
            FreeformTags = freeformTags;
            Id = id;
            Networks = networks;
            Ntps = ntps;
            ScanListenerPortTcp = scanListenerPortTcp;
            ScanListenerPortTcpSsl = scanListenerPortTcpSsl;
            Scans = scans;
            VmNetworks = vmNetworks;
        }
    }
}