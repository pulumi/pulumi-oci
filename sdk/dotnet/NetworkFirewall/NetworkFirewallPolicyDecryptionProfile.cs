// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.NetworkFirewall
{
    /// <summary>
    /// This resource provides the Network Firewall Policy Decryption Profile resource in Oracle Cloud Infrastructure Network Firewall service.
    /// 
    /// Creates a new Decryption Profile for the Network Firewall Policy.
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
    ///     var testNetworkFirewallPolicyDecryptionProfile = new Oci.NetworkFirewall.NetworkFirewallPolicyDecryptionProfile("testNetworkFirewallPolicyDecryptionProfile", new()
    ///     {
    ///         NetworkFirewallPolicyId = oci_network_firewall_network_firewall_policy.Test_network_firewall_policy.Id,
    ///         Type = @var.Network_firewall_policy_decryption_profile_type,
    ///         AreCertificateExtensionsRestricted = @var.Network_firewall_policy_decryption_profile_are_certificate_extensions_restricted,
    ///         IsAutoIncludeAltName = @var.Network_firewall_policy_decryption_profile_is_auto_include_alt_name,
    ///         IsExpiredCertificateBlocked = @var.Network_firewall_policy_decryption_profile_is_expired_certificate_blocked,
    ///         IsOutOfCapacityBlocked = @var.Network_firewall_policy_decryption_profile_is_out_of_capacity_blocked,
    ///         IsRevocationStatusTimeoutBlocked = @var.Network_firewall_policy_decryption_profile_is_revocation_status_timeout_blocked,
    ///         IsUnknownRevocationStatusBlocked = @var.Network_firewall_policy_decryption_profile_is_unknown_revocation_status_blocked,
    ///         IsUnsupportedCipherBlocked = @var.Network_firewall_policy_decryption_profile_is_unsupported_cipher_blocked,
    ///         IsUnsupportedVersionBlocked = @var.Network_firewall_policy_decryption_profile_is_unsupported_version_blocked,
    ///         IsUntrustedIssuerBlocked = @var.Network_firewall_policy_decryption_profile_is_untrusted_issuer_blocked,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// NetworkFirewallPolicyDecryptionProfiles can be imported using the `name`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:NetworkFirewall/networkFirewallPolicyDecryptionProfile:NetworkFirewallPolicyDecryptionProfile test_network_firewall_policy_decryption_profile "networkFirewallPolicies/{networkFirewallPolicyId}/decryptionProfiles/{decryptionProfileName}"
    /// ```
    /// </summary>
    [OciResourceType("oci:NetworkFirewall/networkFirewallPolicyDecryptionProfile:NetworkFirewallPolicyDecryptionProfile")]
    public partial class NetworkFirewallPolicyDecryptionProfile : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) Whether to block sessions if the server's certificate uses extensions other than key usage and/or extended key usage.
        /// </summary>
        [Output("areCertificateExtensionsRestricted")]
        public Output<bool> AreCertificateExtensionsRestricted { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Whether to automatically append SAN to impersonating certificate if server certificate is missing SAN.
        /// </summary>
        [Output("isAutoIncludeAltName")]
        public Output<bool> IsAutoIncludeAltName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Whether to block sessions if server's certificate is expired.
        /// </summary>
        [Output("isExpiredCertificateBlocked")]
        public Output<bool> IsExpiredCertificateBlocked { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Whether to block sessions if the firewall is temporarily unable to decrypt their traffic.
        /// </summary>
        [Output("isOutOfCapacityBlocked")]
        public Output<bool> IsOutOfCapacityBlocked { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Whether to block sessions if the revocation status check for server's certificate does not succeed within the maximum allowed time (defaulting to 5 seconds).
        /// </summary>
        [Output("isRevocationStatusTimeoutBlocked")]
        public Output<bool> IsRevocationStatusTimeoutBlocked { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Whether to block sessions if the revocation status check for server's certificate results in "unknown".
        /// </summary>
        [Output("isUnknownRevocationStatusBlocked")]
        public Output<bool> IsUnknownRevocationStatusBlocked { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Whether to block sessions if SSL cipher suite is not supported.
        /// </summary>
        [Output("isUnsupportedCipherBlocked")]
        public Output<bool> IsUnsupportedCipherBlocked { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Whether to block sessions if SSL version is not supported.
        /// </summary>
        [Output("isUnsupportedVersionBlocked")]
        public Output<bool> IsUnsupportedVersionBlocked { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Whether to block sessions if server's certificate is issued by an untrusted certificate authority (CA).
        /// </summary>
        [Output("isUntrustedIssuerBlocked")]
        public Output<bool> IsUntrustedIssuerBlocked { get; private set; } = null!;

        /// <summary>
        /// Name of the decryption profile.
        /// </summary>
        [Output("name")]
        public Output<string> Name { get; private set; } = null!;

        /// <summary>
        /// Unique Network Firewall Policy identifier
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("networkFirewallPolicyId")]
        public Output<string> NetworkFirewallPolicyId { get; private set; } = null!;

        /// <summary>
        /// OCID of the Network Firewall Policy this decryption profile belongs to.
        /// </summary>
        [Output("parentResourceId")]
        public Output<string> ParentResourceId { get; private set; } = null!;

        /// <summary>
        /// Describes the type of decryption profile. The accepted values are - * SSL_FORWARD_PROXY * SSL_INBOUND_INSPECTION
        /// </summary>
        [Output("type")]
        public Output<string> Type { get; private set; } = null!;


        /// <summary>
        /// Create a NetworkFirewallPolicyDecryptionProfile resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public NetworkFirewallPolicyDecryptionProfile(string name, NetworkFirewallPolicyDecryptionProfileArgs args, CustomResourceOptions? options = null)
            : base("oci:NetworkFirewall/networkFirewallPolicyDecryptionProfile:NetworkFirewallPolicyDecryptionProfile", name, args ?? new NetworkFirewallPolicyDecryptionProfileArgs(), MakeResourceOptions(options, ""))
        {
        }

        private NetworkFirewallPolicyDecryptionProfile(string name, Input<string> id, NetworkFirewallPolicyDecryptionProfileState? state = null, CustomResourceOptions? options = null)
            : base("oci:NetworkFirewall/networkFirewallPolicyDecryptionProfile:NetworkFirewallPolicyDecryptionProfile", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing NetworkFirewallPolicyDecryptionProfile resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static NetworkFirewallPolicyDecryptionProfile Get(string name, Input<string> id, NetworkFirewallPolicyDecryptionProfileState? state = null, CustomResourceOptions? options = null)
        {
            return new NetworkFirewallPolicyDecryptionProfile(name, id, state, options);
        }
    }

    public sealed class NetworkFirewallPolicyDecryptionProfileArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Whether to block sessions if the server's certificate uses extensions other than key usage and/or extended key usage.
        /// </summary>
        [Input("areCertificateExtensionsRestricted")]
        public Input<bool>? AreCertificateExtensionsRestricted { get; set; }

        /// <summary>
        /// (Updatable) Whether to automatically append SAN to impersonating certificate if server certificate is missing SAN.
        /// </summary>
        [Input("isAutoIncludeAltName")]
        public Input<bool>? IsAutoIncludeAltName { get; set; }

        /// <summary>
        /// (Updatable) Whether to block sessions if server's certificate is expired.
        /// </summary>
        [Input("isExpiredCertificateBlocked")]
        public Input<bool>? IsExpiredCertificateBlocked { get; set; }

        /// <summary>
        /// (Updatable) Whether to block sessions if the firewall is temporarily unable to decrypt their traffic.
        /// </summary>
        [Input("isOutOfCapacityBlocked")]
        public Input<bool>? IsOutOfCapacityBlocked { get; set; }

        /// <summary>
        /// (Updatable) Whether to block sessions if the revocation status check for server's certificate does not succeed within the maximum allowed time (defaulting to 5 seconds).
        /// </summary>
        [Input("isRevocationStatusTimeoutBlocked")]
        public Input<bool>? IsRevocationStatusTimeoutBlocked { get; set; }

        /// <summary>
        /// (Updatable) Whether to block sessions if the revocation status check for server's certificate results in "unknown".
        /// </summary>
        [Input("isUnknownRevocationStatusBlocked")]
        public Input<bool>? IsUnknownRevocationStatusBlocked { get; set; }

        /// <summary>
        /// (Updatable) Whether to block sessions if SSL cipher suite is not supported.
        /// </summary>
        [Input("isUnsupportedCipherBlocked")]
        public Input<bool>? IsUnsupportedCipherBlocked { get; set; }

        /// <summary>
        /// (Updatable) Whether to block sessions if SSL version is not supported.
        /// </summary>
        [Input("isUnsupportedVersionBlocked")]
        public Input<bool>? IsUnsupportedVersionBlocked { get; set; }

        /// <summary>
        /// (Updatable) Whether to block sessions if server's certificate is issued by an untrusted certificate authority (CA).
        /// </summary>
        [Input("isUntrustedIssuerBlocked")]
        public Input<bool>? IsUntrustedIssuerBlocked { get; set; }

        /// <summary>
        /// Name of the decryption profile.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// Unique Network Firewall Policy identifier
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("networkFirewallPolicyId", required: true)]
        public Input<string> NetworkFirewallPolicyId { get; set; } = null!;

        /// <summary>
        /// Describes the type of decryption profile. The accepted values are - * SSL_FORWARD_PROXY * SSL_INBOUND_INSPECTION
        /// </summary>
        [Input("type", required: true)]
        public Input<string> Type { get; set; } = null!;

        public NetworkFirewallPolicyDecryptionProfileArgs()
        {
        }
        public static new NetworkFirewallPolicyDecryptionProfileArgs Empty => new NetworkFirewallPolicyDecryptionProfileArgs();
    }

    public sealed class NetworkFirewallPolicyDecryptionProfileState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Whether to block sessions if the server's certificate uses extensions other than key usage and/or extended key usage.
        /// </summary>
        [Input("areCertificateExtensionsRestricted")]
        public Input<bool>? AreCertificateExtensionsRestricted { get; set; }

        /// <summary>
        /// (Updatable) Whether to automatically append SAN to impersonating certificate if server certificate is missing SAN.
        /// </summary>
        [Input("isAutoIncludeAltName")]
        public Input<bool>? IsAutoIncludeAltName { get; set; }

        /// <summary>
        /// (Updatable) Whether to block sessions if server's certificate is expired.
        /// </summary>
        [Input("isExpiredCertificateBlocked")]
        public Input<bool>? IsExpiredCertificateBlocked { get; set; }

        /// <summary>
        /// (Updatable) Whether to block sessions if the firewall is temporarily unable to decrypt their traffic.
        /// </summary>
        [Input("isOutOfCapacityBlocked")]
        public Input<bool>? IsOutOfCapacityBlocked { get; set; }

        /// <summary>
        /// (Updatable) Whether to block sessions if the revocation status check for server's certificate does not succeed within the maximum allowed time (defaulting to 5 seconds).
        /// </summary>
        [Input("isRevocationStatusTimeoutBlocked")]
        public Input<bool>? IsRevocationStatusTimeoutBlocked { get; set; }

        /// <summary>
        /// (Updatable) Whether to block sessions if the revocation status check for server's certificate results in "unknown".
        /// </summary>
        [Input("isUnknownRevocationStatusBlocked")]
        public Input<bool>? IsUnknownRevocationStatusBlocked { get; set; }

        /// <summary>
        /// (Updatable) Whether to block sessions if SSL cipher suite is not supported.
        /// </summary>
        [Input("isUnsupportedCipherBlocked")]
        public Input<bool>? IsUnsupportedCipherBlocked { get; set; }

        /// <summary>
        /// (Updatable) Whether to block sessions if SSL version is not supported.
        /// </summary>
        [Input("isUnsupportedVersionBlocked")]
        public Input<bool>? IsUnsupportedVersionBlocked { get; set; }

        /// <summary>
        /// (Updatable) Whether to block sessions if server's certificate is issued by an untrusted certificate authority (CA).
        /// </summary>
        [Input("isUntrustedIssuerBlocked")]
        public Input<bool>? IsUntrustedIssuerBlocked { get; set; }

        /// <summary>
        /// Name of the decryption profile.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// Unique Network Firewall Policy identifier
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("networkFirewallPolicyId")]
        public Input<string>? NetworkFirewallPolicyId { get; set; }

        /// <summary>
        /// OCID of the Network Firewall Policy this decryption profile belongs to.
        /// </summary>
        [Input("parentResourceId")]
        public Input<string>? ParentResourceId { get; set; }

        /// <summary>
        /// Describes the type of decryption profile. The accepted values are - * SSL_FORWARD_PROXY * SSL_INBOUND_INSPECTION
        /// </summary>
        [Input("type")]
        public Input<string>? Type { get; set; }

        public NetworkFirewallPolicyDecryptionProfileState()
        {
        }
        public static new NetworkFirewallPolicyDecryptionProfileState Empty => new NetworkFirewallPolicyDecryptionProfileState();
    }
}