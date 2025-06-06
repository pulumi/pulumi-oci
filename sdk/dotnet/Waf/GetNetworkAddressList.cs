// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waf
{
    public static class GetNetworkAddressList
    {
        /// <summary>
        /// This data source provides details about a specific Network Address List resource in Oracle Cloud Infrastructure Waf service.
        /// 
        /// Gets a NetworkAddressList by OCID.
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
        ///     var testNetworkAddressList = Oci.Waf.GetNetworkAddressList.Invoke(new()
        ///     {
        ///         NetworkAddressListId = testNetworkAddressListOciWafNetworkAddressList.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetNetworkAddressListResult> InvokeAsync(GetNetworkAddressListArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetNetworkAddressListResult>("oci:Waf/getNetworkAddressList:getNetworkAddressList", args ?? new GetNetworkAddressListArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Network Address List resource in Oracle Cloud Infrastructure Waf service.
        /// 
        /// Gets a NetworkAddressList by OCID.
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
        ///     var testNetworkAddressList = Oci.Waf.GetNetworkAddressList.Invoke(new()
        ///     {
        ///         NetworkAddressListId = testNetworkAddressListOciWafNetworkAddressList.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetNetworkAddressListResult> Invoke(GetNetworkAddressListInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetNetworkAddressListResult>("oci:Waf/getNetworkAddressList:getNetworkAddressList", args ?? new GetNetworkAddressListInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Network Address List resource in Oracle Cloud Infrastructure Waf service.
        /// 
        /// Gets a NetworkAddressList by OCID.
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
        ///     var testNetworkAddressList = Oci.Waf.GetNetworkAddressList.Invoke(new()
        ///     {
        ///         NetworkAddressListId = testNetworkAddressListOciWafNetworkAddressList.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetNetworkAddressListResult> Invoke(GetNetworkAddressListInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetNetworkAddressListResult>("oci:Waf/getNetworkAddressList:getNetworkAddressList", args ?? new GetNetworkAddressListInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetNetworkAddressListArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the NetworkAddressList.
        /// </summary>
        [Input("networkAddressListId", required: true)]
        public string NetworkAddressListId { get; set; } = null!;

        public GetNetworkAddressListArgs()
        {
        }
        public static new GetNetworkAddressListArgs Empty => new GetNetworkAddressListArgs();
    }

    public sealed class GetNetworkAddressListInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the NetworkAddressList.
        /// </summary>
        [Input("networkAddressListId", required: true)]
        public Input<string> NetworkAddressListId { get; set; } = null!;

        public GetNetworkAddressListInvokeArgs()
        {
        }
        public static new GetNetworkAddressListInvokeArgs Empty => new GetNetworkAddressListInvokeArgs();
    }


    [OutputType]
    public sealed class GetNetworkAddressListResult
    {
        /// <summary>
        /// A private IP address or CIDR IP address range.
        /// </summary>
        public readonly ImmutableArray<string> Addresses;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// NetworkAddressList display name, can be renamed.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the NetworkAddressList.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in FAILED state.
        /// </summary>
        public readonly string LifecycleDetails;
        public readonly string NetworkAddressListId;
        /// <summary>
        /// The current state of the NetworkAddressList.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The time the NetworkAddressList was created. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time the NetworkAddressList was updated. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// Type of NetworkAddressList.
        /// </summary>
        public readonly string Type;
        /// <summary>
        /// A list of private address prefixes, each associated with a particular VCN. To specify all addresses in a VCN, use "0.0.0.0/0" for IPv4 and "::/0" for IPv6.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNetworkAddressListVcnAddressResult> VcnAddresses;

        [OutputConstructor]
        private GetNetworkAddressListResult(
            ImmutableArray<string> addresses,

            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string lifecycleDetails,

            string networkAddressListId,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated,

            string type,

            ImmutableArray<Outputs.GetNetworkAddressListVcnAddressResult> vcnAddresses)
        {
            Addresses = addresses;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            NetworkAddressListId = networkAddressListId;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            Type = type;
            VcnAddresses = vcnAddresses;
        }
    }
}
