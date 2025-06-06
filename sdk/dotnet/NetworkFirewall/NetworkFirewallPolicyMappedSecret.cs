// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.NetworkFirewall
{
    /// <summary>
    /// This resource provides the Network Firewall Policy Mapped Secret resource in Oracle Cloud Infrastructure Network Firewall service.
    /// 
    /// Creates a new Mapped Secret for the Network Firewall Policy.
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
    ///     var testNetworkFirewallPolicyMappedSecret = new Oci.NetworkFirewall.NetworkFirewallPolicyMappedSecret("test_network_firewall_policy_mapped_secret", new()
    ///     {
    ///         Name = networkFirewallPolicyMappedSecretName,
    ///         NetworkFirewallPolicyId = testNetworkFirewallPolicy.Id,
    ///         Source = networkFirewallPolicyMappedSecretSource,
    ///         Type = networkFirewallPolicyMappedSecretType,
    ///         VaultSecretId = testSecret.Id,
    ///         VersionNumber = networkFirewallPolicyMappedSecretVersionNumber,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// NetworkFirewallPolicyMappedSecrets can be imported using the `name`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:NetworkFirewall/networkFirewallPolicyMappedSecret:NetworkFirewallPolicyMappedSecret test_network_firewall_policy_mapped_secret "networkFirewallPolicies/{networkFirewallPolicyId}/mappedSecrets/{mappedSecretName}"
    /// ```
    /// </summary>
    [OciResourceType("oci:NetworkFirewall/networkFirewallPolicyMappedSecret:NetworkFirewallPolicyMappedSecret")]
    public partial class NetworkFirewallPolicyMappedSecret : global::Pulumi.CustomResource
    {
        /// <summary>
        /// Unique name to identify the group of urls to be used in the policy rules.
        /// </summary>
        [Output("name")]
        public Output<string> Name { get; private set; } = null!;

        /// <summary>
        /// Unique Network Firewall Policy identifier
        /// </summary>
        [Output("networkFirewallPolicyId")]
        public Output<string> NetworkFirewallPolicyId { get; private set; } = null!;

        /// <summary>
        /// OCID of the Network Firewall Policy this Mapped Secret belongs to.
        /// </summary>
        [Output("parentResourceId")]
        public Output<string> ParentResourceId { get; private set; } = null!;

        /// <summary>
        /// Source of the secrets, where the secrets are stored. The only accepted value is `OCI_VAULT`
        /// </summary>
        [Output("source")]
        public Output<string> Source { get; private set; } = null!;

        /// <summary>
        /// Type of the secrets mapped based on the policy.
        /// * `SSL_INBOUND_INSPECTION`: For Inbound inspection of SSL traffic.
        /// * `SSL_FORWARD_PROXY`: For forward proxy certificates for SSL inspection.
        /// </summary>
        [Output("type")]
        public Output<string> Type { get; private set; } = null!;

        /// <summary>
        /// (Updatable) OCID for the Vault Secret to be used.
        /// </summary>
        [Output("vaultSecretId")]
        public Output<string> VaultSecretId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Version number of the secret to be used.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("versionNumber")]
        public Output<int> VersionNumber { get; private set; } = null!;


        /// <summary>
        /// Create a NetworkFirewallPolicyMappedSecret resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public NetworkFirewallPolicyMappedSecret(string name, NetworkFirewallPolicyMappedSecretArgs args, CustomResourceOptions? options = null)
            : base("oci:NetworkFirewall/networkFirewallPolicyMappedSecret:NetworkFirewallPolicyMappedSecret", name, args ?? new NetworkFirewallPolicyMappedSecretArgs(), MakeResourceOptions(options, ""))
        {
        }

        private NetworkFirewallPolicyMappedSecret(string name, Input<string> id, NetworkFirewallPolicyMappedSecretState? state = null, CustomResourceOptions? options = null)
            : base("oci:NetworkFirewall/networkFirewallPolicyMappedSecret:NetworkFirewallPolicyMappedSecret", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing NetworkFirewallPolicyMappedSecret resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static NetworkFirewallPolicyMappedSecret Get(string name, Input<string> id, NetworkFirewallPolicyMappedSecretState? state = null, CustomResourceOptions? options = null)
        {
            return new NetworkFirewallPolicyMappedSecret(name, id, state, options);
        }
    }

    public sealed class NetworkFirewallPolicyMappedSecretArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Unique name to identify the group of urls to be used in the policy rules.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// Unique Network Firewall Policy identifier
        /// </summary>
        [Input("networkFirewallPolicyId", required: true)]
        public Input<string> NetworkFirewallPolicyId { get; set; } = null!;

        /// <summary>
        /// Source of the secrets, where the secrets are stored. The only accepted value is `OCI_VAULT`
        /// </summary>
        [Input("source", required: true)]
        public Input<string> Source { get; set; } = null!;

        /// <summary>
        /// Type of the secrets mapped based on the policy.
        /// * `SSL_INBOUND_INSPECTION`: For Inbound inspection of SSL traffic.
        /// * `SSL_FORWARD_PROXY`: For forward proxy certificates for SSL inspection.
        /// </summary>
        [Input("type", required: true)]
        public Input<string> Type { get; set; } = null!;

        /// <summary>
        /// (Updatable) OCID for the Vault Secret to be used.
        /// </summary>
        [Input("vaultSecretId", required: true)]
        public Input<string> VaultSecretId { get; set; } = null!;

        /// <summary>
        /// (Updatable) Version number of the secret to be used.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("versionNumber", required: true)]
        public Input<int> VersionNumber { get; set; } = null!;

        public NetworkFirewallPolicyMappedSecretArgs()
        {
        }
        public static new NetworkFirewallPolicyMappedSecretArgs Empty => new NetworkFirewallPolicyMappedSecretArgs();
    }

    public sealed class NetworkFirewallPolicyMappedSecretState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Unique name to identify the group of urls to be used in the policy rules.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// Unique Network Firewall Policy identifier
        /// </summary>
        [Input("networkFirewallPolicyId")]
        public Input<string>? NetworkFirewallPolicyId { get; set; }

        /// <summary>
        /// OCID of the Network Firewall Policy this Mapped Secret belongs to.
        /// </summary>
        [Input("parentResourceId")]
        public Input<string>? ParentResourceId { get; set; }

        /// <summary>
        /// Source of the secrets, where the secrets are stored. The only accepted value is `OCI_VAULT`
        /// </summary>
        [Input("source")]
        public Input<string>? Source { get; set; }

        /// <summary>
        /// Type of the secrets mapped based on the policy.
        /// * `SSL_INBOUND_INSPECTION`: For Inbound inspection of SSL traffic.
        /// * `SSL_FORWARD_PROXY`: For forward proxy certificates for SSL inspection.
        /// </summary>
        [Input("type")]
        public Input<string>? Type { get; set; }

        /// <summary>
        /// (Updatable) OCID for the Vault Secret to be used.
        /// </summary>
        [Input("vaultSecretId")]
        public Input<string>? VaultSecretId { get; set; }

        /// <summary>
        /// (Updatable) Version number of the secret to be used.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("versionNumber")]
        public Input<int>? VersionNumber { get; set; }

        public NetworkFirewallPolicyMappedSecretState()
        {
        }
        public static new NetworkFirewallPolicyMappedSecretState Empty => new NetworkFirewallPolicyMappedSecretState();
    }
}
