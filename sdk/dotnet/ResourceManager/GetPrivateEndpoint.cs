// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ResourceManager
{
    public static class GetPrivateEndpoint
    {
        /// <summary>
        /// This data source provides details about a specific Private Endpoint resource in Oracle Cloud Infrastructure Resource Manager service.
        /// 
        /// Gets the specified private endpoint.
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
        ///     var testPrivateEndpoint = Oci.ResourceManager.GetPrivateEndpoint.Invoke(new()
        ///     {
        ///         PrivateEndpointId = testPrivateEndpointOciResourcemanagerPrivateEndpoint.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetPrivateEndpointResult> InvokeAsync(GetPrivateEndpointArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetPrivateEndpointResult>("oci:ResourceManager/getPrivateEndpoint:getPrivateEndpoint", args ?? new GetPrivateEndpointArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Private Endpoint resource in Oracle Cloud Infrastructure Resource Manager service.
        /// 
        /// Gets the specified private endpoint.
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
        ///     var testPrivateEndpoint = Oci.ResourceManager.GetPrivateEndpoint.Invoke(new()
        ///     {
        ///         PrivateEndpointId = testPrivateEndpointOciResourcemanagerPrivateEndpoint.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetPrivateEndpointResult> Invoke(GetPrivateEndpointInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetPrivateEndpointResult>("oci:ResourceManager/getPrivateEndpoint:getPrivateEndpoint", args ?? new GetPrivateEndpointInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Private Endpoint resource in Oracle Cloud Infrastructure Resource Manager service.
        /// 
        /// Gets the specified private endpoint.
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
        ///     var testPrivateEndpoint = Oci.ResourceManager.GetPrivateEndpoint.Invoke(new()
        ///     {
        ///         PrivateEndpointId = testPrivateEndpointOciResourcemanagerPrivateEndpoint.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetPrivateEndpointResult> Invoke(GetPrivateEndpointInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetPrivateEndpointResult>("oci:ResourceManager/getPrivateEndpoint:getPrivateEndpoint", args ?? new GetPrivateEndpointInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetPrivateEndpointArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the private endpoint.
        /// </summary>
        [Input("privateEndpointId", required: true)]
        public string PrivateEndpointId { get; set; } = null!;

        public GetPrivateEndpointArgs()
        {
        }
        public static new GetPrivateEndpointArgs Empty => new GetPrivateEndpointArgs();
    }

    public sealed class GetPrivateEndpointInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the private endpoint.
        /// </summary>
        [Input("privateEndpointId", required: true)]
        public Input<string> PrivateEndpointId { get; set; } = null!;

        public GetPrivateEndpointInvokeArgs()
        {
        }
        public static new GetPrivateEndpointInvokeArgs Empty => new GetPrivateEndpointInvokeArgs();
    }


    [OutputType]
    public sealed class GetPrivateEndpointResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing this private endpoint details.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// Description of the private endpoint. Avoid entering confidential information.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// DNS Proxy forwards any DNS FQDN queries over into the consumer DNS resolver if the DNS FQDN is included in the dns zones list otherwise it goes to service provider VCN resolver.
        /// </summary>
        public readonly ImmutableArray<string> DnsZones;
        /// <summary>
        /// Free-form tags associated with the resource. Each tag is a key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// Unique identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the private endpoint details.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// When `true`, allows the private endpoint to be used with a configuration source provider.
        /// </summary>
        public readonly bool IsUsedWithConfigurationSourceProvider;
        /// <summary>
        /// An array of network security groups (NSG) that the customer can optionally provide.
        /// </summary>
        public readonly ImmutableArray<string> NsgIdLists;
        public readonly string PrivateEndpointId;
        /// <summary>
        /// The source IPs which resource manager service will use to connect to customer's network. Automatically assigned by Resource Manager Service.
        /// </summary>
        public readonly ImmutableArray<string> SourceIps;
        /// <summary>
        /// The current lifecycle state of the private endpoint.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet within the VCN for the private endpoint.
        /// </summary>
        public readonly string SubnetId;
        /// <summary>
        /// The date and time at which the private endpoint was created. Format is defined by RFC3339. Example: `2020-11-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN for the private endpoint.
        /// </summary>
        public readonly string VcnId;

        [OutputConstructor]
        private GetPrivateEndpointResult(
            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string description,

            string displayName,

            ImmutableArray<string> dnsZones,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            bool isUsedWithConfigurationSourceProvider,

            ImmutableArray<string> nsgIdLists,

            string privateEndpointId,

            ImmutableArray<string> sourceIps,

            string state,

            string subnetId,

            string timeCreated,

            string vcnId)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            DnsZones = dnsZones;
            FreeformTags = freeformTags;
            Id = id;
            IsUsedWithConfigurationSourceProvider = isUsedWithConfigurationSourceProvider;
            NsgIdLists = nsgIdLists;
            PrivateEndpointId = privateEndpointId;
            SourceIps = sourceIps;
            State = state;
            SubnetId = subnetId;
            TimeCreated = timeCreated;
            VcnId = vcnId;
        }
    }
}
