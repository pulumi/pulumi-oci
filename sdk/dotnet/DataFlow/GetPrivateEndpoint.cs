// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataFlow
{
    public static class GetPrivateEndpoint
    {
        /// <summary>
        /// This data source provides details about a specific Private Endpoint resource in Oracle Cloud Infrastructure Data Flow service.
        /// 
        /// Retrieves an private endpoint using a `privateEndpointId`.
        /// 
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
        ///     var testPrivateEndpoint = Oci.DataFlow.GetPrivateEndpoint.Invoke(new()
        ///     {
        ///         PrivateEndpointId = testPrivateEndpointOciDataflowPrivateEndpoint.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetPrivateEndpointResult> InvokeAsync(GetPrivateEndpointArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetPrivateEndpointResult>("oci:DataFlow/getPrivateEndpoint:getPrivateEndpoint", args ?? new GetPrivateEndpointArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Private Endpoint resource in Oracle Cloud Infrastructure Data Flow service.
        /// 
        /// Retrieves an private endpoint using a `privateEndpointId`.
        /// 
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
        ///     var testPrivateEndpoint = Oci.DataFlow.GetPrivateEndpoint.Invoke(new()
        ///     {
        ///         PrivateEndpointId = testPrivateEndpointOciDataflowPrivateEndpoint.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetPrivateEndpointResult> Invoke(GetPrivateEndpointInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetPrivateEndpointResult>("oci:DataFlow/getPrivateEndpoint:getPrivateEndpoint", args ?? new GetPrivateEndpointInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Private Endpoint resource in Oracle Cloud Infrastructure Data Flow service.
        /// 
        /// Retrieves an private endpoint using a `privateEndpointId`.
        /// 
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
        ///     var testPrivateEndpoint = Oci.DataFlow.GetPrivateEndpoint.Invoke(new()
        ///     {
        ///         PrivateEndpointId = testPrivateEndpointOciDataflowPrivateEndpoint.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetPrivateEndpointResult> Invoke(GetPrivateEndpointInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetPrivateEndpointResult>("oci:DataFlow/getPrivateEndpoint:getPrivateEndpoint", args ?? new GetPrivateEndpointInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetPrivateEndpointArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The unique ID for a private endpoint.
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
        /// The unique ID for a private endpoint.
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
        /// The OCID of a compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// A user-friendly description. Avoid entering confidential information.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// A user-friendly name. It does not have to be unique. Avoid entering confidential information.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// An array of DNS zone names. Example: `[ "app.examplecorp.com", "app.examplecorp2.com" ]`
        /// </summary>
        public readonly ImmutableArray<string> DnsZones;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The OCID of a private endpoint.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The detailed messages about the lifecycle state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The maximum number of hosts to be accessed through the private endpoint. This value is used to calculate the relevant CIDR block and should be a multiple of 256.  If the value is not a multiple of 256, it is rounded up to the next multiple of 256. For example, 300 is rounded up to 512.
        /// </summary>
        public readonly int MaxHostCount;
        /// <summary>
        /// An array of network security group OCIDs.
        /// </summary>
        public readonly ImmutableArray<string> NsgIds;
        /// <summary>
        /// The OCID of the user who created the resource.
        /// </summary>
        public readonly string OwnerPrincipalId;
        /// <summary>
        /// The username of the user who created the resource.  If the username of the owner does not exist, `null` will be returned and the caller should refer to the ownerPrincipalId value instead.
        /// </summary>
        public readonly string OwnerUserName;
        public readonly string PrivateEndpointId;
        /// <summary>
        /// An array of fqdn/port pairs used to create private endpoint. Each object is a simple key-value pair with FQDN as key and port number as value. [ { fqdn: "scan1.oracle.com", port: "1521"}, { fqdn: "scan2.oracle.com", port: "1521" } ]
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPrivateEndpointScanDetailResult> ScanDetails;
        /// <summary>
        /// The current state of this private endpoint.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The OCID of a subnet.
        /// </summary>
        public readonly string SubnetId;
        /// <summary>
        /// The date and time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetPrivateEndpointResult(
            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string description,

            string displayName,

            ImmutableArray<string> dnsZones,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string lifecycleDetails,

            int maxHostCount,

            ImmutableArray<string> nsgIds,

            string ownerPrincipalId,

            string ownerUserName,

            string privateEndpointId,

            ImmutableArray<Outputs.GetPrivateEndpointScanDetailResult> scanDetails,

            string state,

            string subnetId,

            string timeCreated,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            DnsZones = dnsZones;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            MaxHostCount = maxHostCount;
            NsgIds = nsgIds;
            OwnerPrincipalId = ownerPrincipalId;
            OwnerUserName = ownerUserName;
            PrivateEndpointId = privateEndpointId;
            ScanDetails = scanDetails;
            State = state;
            SubnetId = subnetId;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
