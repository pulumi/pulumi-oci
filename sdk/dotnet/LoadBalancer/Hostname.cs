// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LoadBalancer
{
    /// <summary>
    /// ## Example Usage
    /// 
    /// ## Import
    /// 
    /// Hostnames can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:LoadBalancer/hostname:Hostname test_hostname "loadBalancers/{loadBalancerId}/hostnames/{name}"
    /// ```
    /// </summary>
    [OciResourceType("oci:LoadBalancer/hostname:Hostname")]
    public partial class Hostname : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) A virtual hostname. For more information about virtual hostname string construction, see [Managing Request Routing](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/managingrequest.htm#routing).  Example: `app.example.com`
        /// </summary>
        [Output("hostname")]
        public Output<string> VirtualHostname { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to add the hostname to.
        /// </summary>
        [Output("loadBalancerId")]
        public Output<string> LoadBalancerId { get; private set; } = null!;

        /// <summary>
        /// A friendly name for the hostname resource. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `example_hostname_001` 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("name")]
        public Output<string> Name { get; private set; } = null!;

        [Output("state")]
        public Output<string> State { get; private set; } = null!;


        /// <summary>
        /// Create a Hostname resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public Hostname(string name, HostnameArgs args, CustomResourceOptions? options = null)
            : base("oci:LoadBalancer/hostname:Hostname", name, args ?? new HostnameArgs(), MakeResourceOptions(options, ""))
        {
        }

        private Hostname(string name, Input<string> id, HostnameState? state = null, CustomResourceOptions? options = null)
            : base("oci:LoadBalancer/hostname:Hostname", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing Hostname resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static Hostname Get(string name, Input<string> id, HostnameState? state = null, CustomResourceOptions? options = null)
        {
            return new Hostname(name, id, state, options);
        }
    }

    public sealed class HostnameArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) A virtual hostname. For more information about virtual hostname string construction, see [Managing Request Routing](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/managingrequest.htm#routing).  Example: `app.example.com`
        /// </summary>
        [Input("hostname", required: true)]
        public Input<string> VirtualHostname { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to add the hostname to.
        /// </summary>
        [Input("loadBalancerId", required: true)]
        public Input<string> LoadBalancerId { get; set; } = null!;

        /// <summary>
        /// A friendly name for the hostname resource. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `example_hostname_001` 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        public HostnameArgs()
        {
        }
        public static new HostnameArgs Empty => new HostnameArgs();
    }

    public sealed class HostnameState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) A virtual hostname. For more information about virtual hostname string construction, see [Managing Request Routing](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/managingrequest.htm#routing).  Example: `app.example.com`
        /// </summary>
        [Input("hostname")]
        public Input<string>? VirtualHostname { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to add the hostname to.
        /// </summary>
        [Input("loadBalancerId")]
        public Input<string>? LoadBalancerId { get; set; }

        /// <summary>
        /// A friendly name for the hostname resource. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `example_hostname_001` 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        [Input("state")]
        public Input<string>? State { get; set; }

        public HostnameState()
        {
        }
        public static new HostnameState Empty => new HostnameState();
    }
}
