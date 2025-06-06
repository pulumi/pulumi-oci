// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.NetworkLoadBalancer
{
    /// <summary>
    /// This resource provides the Listener resource in Oracle Cloud Infrastructure Network Load Balancer service.
    /// 
    /// Adds a listener to a network load balancer.
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
    ///     var testListener = new Oci.NetworkLoadBalancer.Listener("test_listener", new()
    ///     {
    ///         DefaultBackendSetName = testBackendSet.Name,
    ///         Name = listenerName,
    ///         NetworkLoadBalancerId = testNetworkLoadBalancer.Id,
    ///         Port = listenerPort,
    ///         Protocol = listenerProtocol,
    ///         IpVersion = listenerIpVersion,
    ///         IsPpv2enabled = listenerIsPpv2enabled,
    ///         L3ipIdleTimeout = listenerL3ipIdleTimeout,
    ///         TcpIdleTimeout = listenerTcpIdleTimeout,
    ///         UdpIdleTimeout = listenerUdpIdleTimeout,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// Listeners can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:NetworkLoadBalancer/listener:Listener test_listener "networkLoadBalancers/{networkLoadBalancerId}/listeners/{listenerName}"
    /// ```
    /// </summary>
    [OciResourceType("oci:NetworkLoadBalancer/listener:Listener")]
    public partial class Listener : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) The name of the associated backend set.  Example: `example_backend_set`
        /// </summary>
        [Output("defaultBackendSetName")]
        public Output<string> DefaultBackendSetName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) IP version associated with the listener.
        /// </summary>
        [Output("ipVersion")]
        public Output<string> IpVersion { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Property to enable/disable PPv2 feature for this listener.
        /// </summary>
        [Output("isPpv2enabled")]
        public Output<bool> IsPpv2enabled { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The duration for L3IP idle timeout in seconds. Example: `200`
        /// </summary>
        [Output("l3ipIdleTimeout")]
        public Output<int> L3ipIdleTimeout { get; private set; } = null!;

        /// <summary>
        /// A friendly name for the listener. It must be unique and it cannot be changed.  Example: `example_listener`
        /// </summary>
        [Output("name")]
        public Output<string> Name { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
        /// </summary>
        [Output("networkLoadBalancerId")]
        public Output<string> NetworkLoadBalancerId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The communication port for the listener.  Example: `80`
        /// </summary>
        [Output("port")]
        public Output<int> Port { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The protocol on which the listener accepts connection requests. For public network load balancers, ANY protocol refers to TCP/UDP with the wildcard port. For private network load balancers, ANY protocol refers to TCP/UDP/ICMP (note that ICMP requires isPreserveSourceDestination to be set to true). "ListNetworkLoadBalancersProtocols" API is deprecated and it will not return the updated values. Use the allowed values for the protocol instead.  Example: `TCP`
        /// </summary>
        [Output("protocol")]
        public Output<string> Protocol { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The duration for TCP idle timeout in seconds. Example: `300`
        /// </summary>
        [Output("tcpIdleTimeout")]
        public Output<int> TcpIdleTimeout { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The duration for UDP idle timeout in seconds. Example: `120` 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("udpIdleTimeout")]
        public Output<int> UdpIdleTimeout { get; private set; } = null!;


        /// <summary>
        /// Create a Listener resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public Listener(string name, ListenerArgs args, CustomResourceOptions? options = null)
            : base("oci:NetworkLoadBalancer/listener:Listener", name, args ?? new ListenerArgs(), MakeResourceOptions(options, ""))
        {
        }

        private Listener(string name, Input<string> id, ListenerState? state = null, CustomResourceOptions? options = null)
            : base("oci:NetworkLoadBalancer/listener:Listener", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing Listener resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static Listener Get(string name, Input<string> id, ListenerState? state = null, CustomResourceOptions? options = null)
        {
            return new Listener(name, id, state, options);
        }
    }

    public sealed class ListenerArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The name of the associated backend set.  Example: `example_backend_set`
        /// </summary>
        [Input("defaultBackendSetName", required: true)]
        public Input<string> DefaultBackendSetName { get; set; } = null!;

        /// <summary>
        /// (Updatable) IP version associated with the listener.
        /// </summary>
        [Input("ipVersion")]
        public Input<string>? IpVersion { get; set; }

        /// <summary>
        /// (Updatable) Property to enable/disable PPv2 feature for this listener.
        /// </summary>
        [Input("isPpv2enabled")]
        public Input<bool>? IsPpv2enabled { get; set; }

        /// <summary>
        /// (Updatable) The duration for L3IP idle timeout in seconds. Example: `200`
        /// </summary>
        [Input("l3ipIdleTimeout")]
        public Input<int>? L3ipIdleTimeout { get; set; }

        /// <summary>
        /// A friendly name for the listener. It must be unique and it cannot be changed.  Example: `example_listener`
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
        /// </summary>
        [Input("networkLoadBalancerId", required: true)]
        public Input<string> NetworkLoadBalancerId { get; set; } = null!;

        /// <summary>
        /// (Updatable) The communication port for the listener.  Example: `80`
        /// </summary>
        [Input("port", required: true)]
        public Input<int> Port { get; set; } = null!;

        /// <summary>
        /// (Updatable) The protocol on which the listener accepts connection requests. For public network load balancers, ANY protocol refers to TCP/UDP with the wildcard port. For private network load balancers, ANY protocol refers to TCP/UDP/ICMP (note that ICMP requires isPreserveSourceDestination to be set to true). "ListNetworkLoadBalancersProtocols" API is deprecated and it will not return the updated values. Use the allowed values for the protocol instead.  Example: `TCP`
        /// </summary>
        [Input("protocol", required: true)]
        public Input<string> Protocol { get; set; } = null!;

        /// <summary>
        /// (Updatable) The duration for TCP idle timeout in seconds. Example: `300`
        /// </summary>
        [Input("tcpIdleTimeout")]
        public Input<int>? TcpIdleTimeout { get; set; }

        /// <summary>
        /// (Updatable) The duration for UDP idle timeout in seconds. Example: `120` 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("udpIdleTimeout")]
        public Input<int>? UdpIdleTimeout { get; set; }

        public ListenerArgs()
        {
        }
        public static new ListenerArgs Empty => new ListenerArgs();
    }

    public sealed class ListenerState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The name of the associated backend set.  Example: `example_backend_set`
        /// </summary>
        [Input("defaultBackendSetName")]
        public Input<string>? DefaultBackendSetName { get; set; }

        /// <summary>
        /// (Updatable) IP version associated with the listener.
        /// </summary>
        [Input("ipVersion")]
        public Input<string>? IpVersion { get; set; }

        /// <summary>
        /// (Updatable) Property to enable/disable PPv2 feature for this listener.
        /// </summary>
        [Input("isPpv2enabled")]
        public Input<bool>? IsPpv2enabled { get; set; }

        /// <summary>
        /// (Updatable) The duration for L3IP idle timeout in seconds. Example: `200`
        /// </summary>
        [Input("l3ipIdleTimeout")]
        public Input<int>? L3ipIdleTimeout { get; set; }

        /// <summary>
        /// A friendly name for the listener. It must be unique and it cannot be changed.  Example: `example_listener`
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
        /// </summary>
        [Input("networkLoadBalancerId")]
        public Input<string>? NetworkLoadBalancerId { get; set; }

        /// <summary>
        /// (Updatable) The communication port for the listener.  Example: `80`
        /// </summary>
        [Input("port")]
        public Input<int>? Port { get; set; }

        /// <summary>
        /// (Updatable) The protocol on which the listener accepts connection requests. For public network load balancers, ANY protocol refers to TCP/UDP with the wildcard port. For private network load balancers, ANY protocol refers to TCP/UDP/ICMP (note that ICMP requires isPreserveSourceDestination to be set to true). "ListNetworkLoadBalancersProtocols" API is deprecated and it will not return the updated values. Use the allowed values for the protocol instead.  Example: `TCP`
        /// </summary>
        [Input("protocol")]
        public Input<string>? Protocol { get; set; }

        /// <summary>
        /// (Updatable) The duration for TCP idle timeout in seconds. Example: `300`
        /// </summary>
        [Input("tcpIdleTimeout")]
        public Input<int>? TcpIdleTimeout { get; set; }

        /// <summary>
        /// (Updatable) The duration for UDP idle timeout in seconds. Example: `120` 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("udpIdleTimeout")]
        public Input<int>? UdpIdleTimeout { get; set; }

        public ListenerState()
        {
        }
        public static new ListenerState Empty => new ListenerState();
    }
}
