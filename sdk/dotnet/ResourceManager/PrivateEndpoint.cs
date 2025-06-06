// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ResourceManager
{
    /// <summary>
    /// This resource provides the Private Endpoint resource in Oracle Cloud Infrastructure Resource Manager service.
    /// 
    /// Creates a a private endpoint in the specified compartment.
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using System.Collections.Generic;
    /// using System.Linq;
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// return await Deployment.RunAsync(() =&gt; 
    /// {
    ///     var testPrivateEndpoint = new Oci.ResourceManager.PrivateEndpoint("test_private_endpoint", new()
    ///     {
    ///         CompartmentId = compartmentId,
    ///         DisplayName = privateEndpointDisplayName,
    ///         SubnetId = testSubnet.Id,
    ///         VcnId = testVcn.Id,
    ///         DefinedTags = 
    ///         {
    ///             { "Operations.CostCenter", "42" },
    ///         },
    ///         Description = privateEndpointDescription,
    ///         DnsZones = privateEndpointDnsZones,
    ///         FreeformTags = 
    ///         {
    ///             { "Department", "Finance" },
    ///         },
    ///         IsUsedWithConfigurationSourceProvider = privateEndpointIsUsedWithConfigurationSourceProvider,
    ///         NsgIdLists = privateEndpointNsgIdList,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// PrivateEndpoints can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:ResourceManager/privateEndpoint:PrivateEndpoint test_private_endpoint "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:ResourceManager/privateEndpoint:PrivateEndpoint")]
    public partial class PrivateEndpoint : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing this private endpoint details.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Description of the private endpoint. Avoid entering confidential information.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The private endpoint display name. Avoid entering confidential information.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) DNS Proxy forwards any DNS FQDN queries over into the consumer DNS resolver if the DNS FQDN is included in the dns zones list otherwise it goes to service provider VCN resolver.
        /// </summary>
        [Output("dnsZones")]
        public Output<ImmutableArray<string>> DnsZones { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags associated with the resource. Each tag is a key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) When `true`, allows the private endpoint to be used with a configuration source provider.
        /// </summary>
        [Output("isUsedWithConfigurationSourceProvider")]
        public Output<bool> IsUsedWithConfigurationSourceProvider { get; private set; } = null!;

        /// <summary>
        /// (Updatable) An array of network security group (NSG) [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the private endpoint. Order does not matter.
        /// </summary>
        [Output("nsgIdLists")]
        public Output<ImmutableArray<string>> NsgIdLists { get; private set; } = null!;

        /// <summary>
        /// The source IPs which resource manager service will use to connect to customer's network. Automatically assigned by Resource Manager Service.
        /// </summary>
        [Output("sourceIps")]
        public Output<ImmutableArray<string>> SourceIps { get; private set; } = null!;

        /// <summary>
        /// The current lifecycle state of the private endpoint.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet within the VCN for the private endpoint.
        /// </summary>
        [Output("subnetId")]
        public Output<string> SubnetId { get; private set; } = null!;

        /// <summary>
        /// The date and time at which the private endpoint was created. Format is defined by RFC3339. Example: `2020-11-25T21:10:29.600Z`
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN for the private endpoint.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("vcnId")]
        public Output<string> VcnId { get; private set; } = null!;


        /// <summary>
        /// Create a PrivateEndpoint resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public PrivateEndpoint(string name, PrivateEndpointArgs args, CustomResourceOptions? options = null)
            : base("oci:ResourceManager/privateEndpoint:PrivateEndpoint", name, args ?? new PrivateEndpointArgs(), MakeResourceOptions(options, ""))
        {
        }

        private PrivateEndpoint(string name, Input<string> id, PrivateEndpointState? state = null, CustomResourceOptions? options = null)
            : base("oci:ResourceManager/privateEndpoint:PrivateEndpoint", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing PrivateEndpoint resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static PrivateEndpoint Get(string name, Input<string> id, PrivateEndpointState? state = null, CustomResourceOptions? options = null)
        {
            return new PrivateEndpoint(name, id, state, options);
        }
    }

    public sealed class PrivateEndpointArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing this private endpoint details.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Description of the private endpoint. Avoid entering confidential information.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) The private endpoint display name. Avoid entering confidential information.
        /// </summary>
        [Input("displayName", required: true)]
        public Input<string> DisplayName { get; set; } = null!;

        [Input("dnsZones")]
        private InputList<string>? _dnsZones;

        /// <summary>
        /// (Updatable) DNS Proxy forwards any DNS FQDN queries over into the consumer DNS resolver if the DNS FQDN is included in the dns zones list otherwise it goes to service provider VCN resolver.
        /// </summary>
        public InputList<string> DnsZones
        {
            get => _dnsZones ?? (_dnsZones = new InputList<string>());
            set => _dnsZones = value;
        }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags associated with the resource. Each tag is a key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) When `true`, allows the private endpoint to be used with a configuration source provider.
        /// </summary>
        [Input("isUsedWithConfigurationSourceProvider")]
        public Input<bool>? IsUsedWithConfigurationSourceProvider { get; set; }

        [Input("nsgIdLists")]
        private InputList<string>? _nsgIdLists;

        /// <summary>
        /// (Updatable) An array of network security group (NSG) [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the private endpoint. Order does not matter.
        /// </summary>
        public InputList<string> NsgIdLists
        {
            get => _nsgIdLists ?? (_nsgIdLists = new InputList<string>());
            set => _nsgIdLists = value;
        }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet within the VCN for the private endpoint.
        /// </summary>
        [Input("subnetId", required: true)]
        public Input<string> SubnetId { get; set; } = null!;

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN for the private endpoint.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("vcnId", required: true)]
        public Input<string> VcnId { get; set; } = null!;

        public PrivateEndpointArgs()
        {
        }
        public static new PrivateEndpointArgs Empty => new PrivateEndpointArgs();
    }

    public sealed class PrivateEndpointState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing this private endpoint details.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Description of the private endpoint. Avoid entering confidential information.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) The private endpoint display name. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("dnsZones")]
        private InputList<string>? _dnsZones;

        /// <summary>
        /// (Updatable) DNS Proxy forwards any DNS FQDN queries over into the consumer DNS resolver if the DNS FQDN is included in the dns zones list otherwise it goes to service provider VCN resolver.
        /// </summary>
        public InputList<string> DnsZones
        {
            get => _dnsZones ?? (_dnsZones = new InputList<string>());
            set => _dnsZones = value;
        }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags associated with the resource. Each tag is a key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) When `true`, allows the private endpoint to be used with a configuration source provider.
        /// </summary>
        [Input("isUsedWithConfigurationSourceProvider")]
        public Input<bool>? IsUsedWithConfigurationSourceProvider { get; set; }

        [Input("nsgIdLists")]
        private InputList<string>? _nsgIdLists;

        /// <summary>
        /// (Updatable) An array of network security group (NSG) [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the private endpoint. Order does not matter.
        /// </summary>
        public InputList<string> NsgIdLists
        {
            get => _nsgIdLists ?? (_nsgIdLists = new InputList<string>());
            set => _nsgIdLists = value;
        }

        [Input("sourceIps")]
        private InputList<string>? _sourceIps;

        /// <summary>
        /// The source IPs which resource manager service will use to connect to customer's network. Automatically assigned by Resource Manager Service.
        /// </summary>
        public InputList<string> SourceIps
        {
            get => _sourceIps ?? (_sourceIps = new InputList<string>());
            set => _sourceIps = value;
        }

        /// <summary>
        /// The current lifecycle state of the private endpoint.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet within the VCN for the private endpoint.
        /// </summary>
        [Input("subnetId")]
        public Input<string>? SubnetId { get; set; }

        /// <summary>
        /// The date and time at which the private endpoint was created. Format is defined by RFC3339. Example: `2020-11-25T21:10:29.600Z`
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN for the private endpoint.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("vcnId")]
        public Input<string>? VcnId { get; set; }

        public PrivateEndpointState()
        {
        }
        public static new PrivateEndpointState Empty => new PrivateEndpointState();
    }
}
