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
    /// This resource provides the Network Firewall Policy Application resource in Oracle Cloud Infrastructure Network Firewall service.
    /// 
    /// Creates a new Application inside the Network Firewall Policy.
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
    ///     var testNetworkFirewallPolicyApplication = new Oci.NetworkFirewall.NetworkFirewallPolicyApplication("testNetworkFirewallPolicyApplication", new()
    ///     {
    ///         IcmpType = @var.Network_firewall_policy_application_icmp_type,
    ///         NetworkFirewallPolicyId = oci_network_firewall_network_firewall_policy.Test_network_firewall_policy.Id,
    ///         Type = @var.Network_firewall_policy_application_type,
    ///         IcmpCode = @var.Network_firewall_policy_application_icmp_code,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// NetworkFirewallPolicyApplications can be imported using the `name`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:NetworkFirewall/networkFirewallPolicyApplication:NetworkFirewallPolicyApplication test_network_firewall_policy_application "networkFirewallPolicies/{networkFirewallPolicyId}/applications/{applicationName}"
    /// ```
    /// </summary>
    [OciResourceType("oci:NetworkFirewall/networkFirewallPolicyApplication:NetworkFirewallPolicyApplication")]
    public partial class NetworkFirewallPolicyApplication : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) The value of the ICMP/ICMP_V6 message Code (subtype) field as defined by [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.1).
        /// </summary>
        [Output("icmpCode")]
        public Output<int> IcmpCode { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The value of the ICMP/IMCP_V6 message Type field as defined by [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.1).
        /// </summary>
        [Output("icmpType")]
        public Output<int> IcmpType { get; private set; } = null!;

        /// <summary>
        /// Name of the application
        /// </summary>
        [Output("name")]
        public Output<string> Name { get; private set; } = null!;

        /// <summary>
        /// Unique Network Firewall Policy identifier
        /// </summary>
        [Output("networkFirewallPolicyId")]
        public Output<string> NetworkFirewallPolicyId { get; private set; } = null!;

        /// <summary>
        /// OCID of the Network Firewall Policy this application belongs to.
        /// </summary>
        [Output("parentResourceId")]
        public Output<string> ParentResourceId { get; private set; } = null!;

        /// <summary>
        /// Describes the type of application. The accepted values are - * ICMP * ICMP_V6
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("type")]
        public Output<string> Type { get; private set; } = null!;


        /// <summary>
        /// Create a NetworkFirewallPolicyApplication resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public NetworkFirewallPolicyApplication(string name, NetworkFirewallPolicyApplicationArgs args, CustomResourceOptions? options = null)
            : base("oci:NetworkFirewall/networkFirewallPolicyApplication:NetworkFirewallPolicyApplication", name, args ?? new NetworkFirewallPolicyApplicationArgs(), MakeResourceOptions(options, ""))
        {
        }

        private NetworkFirewallPolicyApplication(string name, Input<string> id, NetworkFirewallPolicyApplicationState? state = null, CustomResourceOptions? options = null)
            : base("oci:NetworkFirewall/networkFirewallPolicyApplication:NetworkFirewallPolicyApplication", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing NetworkFirewallPolicyApplication resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static NetworkFirewallPolicyApplication Get(string name, Input<string> id, NetworkFirewallPolicyApplicationState? state = null, CustomResourceOptions? options = null)
        {
            return new NetworkFirewallPolicyApplication(name, id, state, options);
        }
    }

    public sealed class NetworkFirewallPolicyApplicationArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The value of the ICMP/ICMP_V6 message Code (subtype) field as defined by [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.1).
        /// </summary>
        [Input("icmpCode")]
        public Input<int>? IcmpCode { get; set; }

        /// <summary>
        /// (Updatable) The value of the ICMP/IMCP_V6 message Type field as defined by [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.1).
        /// </summary>
        [Input("icmpType", required: true)]
        public Input<int> IcmpType { get; set; } = null!;

        /// <summary>
        /// Name of the application
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// Unique Network Firewall Policy identifier
        /// </summary>
        [Input("networkFirewallPolicyId", required: true)]
        public Input<string> NetworkFirewallPolicyId { get; set; } = null!;

        /// <summary>
        /// Describes the type of application. The accepted values are - * ICMP * ICMP_V6
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("type", required: true)]
        public Input<string> Type { get; set; } = null!;

        public NetworkFirewallPolicyApplicationArgs()
        {
        }
        public static new NetworkFirewallPolicyApplicationArgs Empty => new NetworkFirewallPolicyApplicationArgs();
    }

    public sealed class NetworkFirewallPolicyApplicationState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The value of the ICMP/ICMP_V6 message Code (subtype) field as defined by [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.1).
        /// </summary>
        [Input("icmpCode")]
        public Input<int>? IcmpCode { get; set; }

        /// <summary>
        /// (Updatable) The value of the ICMP/IMCP_V6 message Type field as defined by [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.1).
        /// </summary>
        [Input("icmpType")]
        public Input<int>? IcmpType { get; set; }

        /// <summary>
        /// Name of the application
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// Unique Network Firewall Policy identifier
        /// </summary>
        [Input("networkFirewallPolicyId")]
        public Input<string>? NetworkFirewallPolicyId { get; set; }

        /// <summary>
        /// OCID of the Network Firewall Policy this application belongs to.
        /// </summary>
        [Input("parentResourceId")]
        public Input<string>? ParentResourceId { get; set; }

        /// <summary>
        /// Describes the type of application. The accepted values are - * ICMP * ICMP_V6
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("type")]
        public Input<string>? Type { get; set; }

        public NetworkFirewallPolicyApplicationState()
        {
        }
        public static new NetworkFirewallPolicyApplicationState Empty => new NetworkFirewallPolicyApplicationState();
    }
}