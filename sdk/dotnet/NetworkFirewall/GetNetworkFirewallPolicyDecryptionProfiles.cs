// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.NetworkFirewall
{
    public static class GetNetworkFirewallPolicyDecryptionProfiles
    {
        /// <summary>
        /// This data source provides the list of Network Firewall Policy Decryption Profiles in Oracle Cloud Infrastructure Network Firewall service.
        /// 
        /// Returns a list of Decryption Profile for the Network Firewall Policy.
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
        ///     var testNetworkFirewallPolicyDecryptionProfiles = Oci.NetworkFirewall.GetNetworkFirewallPolicyDecryptionProfiles.Invoke(new()
        ///     {
        ///         NetworkFirewallPolicyId = testNetworkFirewallPolicy.Id,
        ///         DisplayName = networkFirewallPolicyDecryptionProfileDisplayName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetNetworkFirewallPolicyDecryptionProfilesResult> InvokeAsync(GetNetworkFirewallPolicyDecryptionProfilesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetNetworkFirewallPolicyDecryptionProfilesResult>("oci:NetworkFirewall/getNetworkFirewallPolicyDecryptionProfiles:getNetworkFirewallPolicyDecryptionProfiles", args ?? new GetNetworkFirewallPolicyDecryptionProfilesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Network Firewall Policy Decryption Profiles in Oracle Cloud Infrastructure Network Firewall service.
        /// 
        /// Returns a list of Decryption Profile for the Network Firewall Policy.
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
        ///     var testNetworkFirewallPolicyDecryptionProfiles = Oci.NetworkFirewall.GetNetworkFirewallPolicyDecryptionProfiles.Invoke(new()
        ///     {
        ///         NetworkFirewallPolicyId = testNetworkFirewallPolicy.Id,
        ///         DisplayName = networkFirewallPolicyDecryptionProfileDisplayName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetNetworkFirewallPolicyDecryptionProfilesResult> Invoke(GetNetworkFirewallPolicyDecryptionProfilesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetNetworkFirewallPolicyDecryptionProfilesResult>("oci:NetworkFirewall/getNetworkFirewallPolicyDecryptionProfiles:getNetworkFirewallPolicyDecryptionProfiles", args ?? new GetNetworkFirewallPolicyDecryptionProfilesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Network Firewall Policy Decryption Profiles in Oracle Cloud Infrastructure Network Firewall service.
        /// 
        /// Returns a list of Decryption Profile for the Network Firewall Policy.
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
        ///     var testNetworkFirewallPolicyDecryptionProfiles = Oci.NetworkFirewall.GetNetworkFirewallPolicyDecryptionProfiles.Invoke(new()
        ///     {
        ///         NetworkFirewallPolicyId = testNetworkFirewallPolicy.Id,
        ///         DisplayName = networkFirewallPolicyDecryptionProfileDisplayName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetNetworkFirewallPolicyDecryptionProfilesResult> Invoke(GetNetworkFirewallPolicyDecryptionProfilesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetNetworkFirewallPolicyDecryptionProfilesResult>("oci:NetworkFirewall/getNetworkFirewallPolicyDecryptionProfiles:getNetworkFirewallPolicyDecryptionProfiles", args ?? new GetNetworkFirewallPolicyDecryptionProfilesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetNetworkFirewallPolicyDecryptionProfilesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetNetworkFirewallPolicyDecryptionProfilesFilterArgs>? _filters;
        public List<Inputs.GetNetworkFirewallPolicyDecryptionProfilesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetNetworkFirewallPolicyDecryptionProfilesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Unique Network Firewall Policy identifier
        /// </summary>
        [Input("networkFirewallPolicyId", required: true)]
        public string NetworkFirewallPolicyId { get; set; } = null!;

        public GetNetworkFirewallPolicyDecryptionProfilesArgs()
        {
        }
        public static new GetNetworkFirewallPolicyDecryptionProfilesArgs Empty => new GetNetworkFirewallPolicyDecryptionProfilesArgs();
    }

    public sealed class GetNetworkFirewallPolicyDecryptionProfilesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetNetworkFirewallPolicyDecryptionProfilesFilterInputArgs>? _filters;
        public InputList<Inputs.GetNetworkFirewallPolicyDecryptionProfilesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetNetworkFirewallPolicyDecryptionProfilesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Unique Network Firewall Policy identifier
        /// </summary>
        [Input("networkFirewallPolicyId", required: true)]
        public Input<string> NetworkFirewallPolicyId { get; set; } = null!;

        public GetNetworkFirewallPolicyDecryptionProfilesInvokeArgs()
        {
        }
        public static new GetNetworkFirewallPolicyDecryptionProfilesInvokeArgs Empty => new GetNetworkFirewallPolicyDecryptionProfilesInvokeArgs();
    }


    [OutputType]
    public sealed class GetNetworkFirewallPolicyDecryptionProfilesResult
    {
        /// <summary>
        /// The list of decryption_profile_summary_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNetworkFirewallPolicyDecryptionProfilesDecryptionProfileSummaryCollectionResult> DecryptionProfileSummaryCollections;
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetNetworkFirewallPolicyDecryptionProfilesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string NetworkFirewallPolicyId;

        [OutputConstructor]
        private GetNetworkFirewallPolicyDecryptionProfilesResult(
            ImmutableArray<Outputs.GetNetworkFirewallPolicyDecryptionProfilesDecryptionProfileSummaryCollectionResult> decryptionProfileSummaryCollections,

            string? displayName,

            ImmutableArray<Outputs.GetNetworkFirewallPolicyDecryptionProfilesFilterResult> filters,

            string id,

            string networkFirewallPolicyId)
        {
            DecryptionProfileSummaryCollections = decryptionProfileSummaryCollections;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            NetworkFirewallPolicyId = networkFirewallPolicyId;
        }
    }
}
