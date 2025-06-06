// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.NetworkLoadBalancer
{
    public static class GetListener
    {
        /// <summary>
        /// This data source provides details about a specific Listener resource in Oracle Cloud Infrastructure Network Load Balancer service.
        /// 
        /// Retrieves listener properties associated with a given network load balancer and listener name.
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
        ///     var testListener = Oci.NetworkLoadBalancer.GetListener.Invoke(new()
        ///     {
        ///         ListenerName = testListenerOciNetworkLoadBalancerListener.Name,
        ///         NetworkLoadBalancerId = testNetworkLoadBalancer.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetListenerResult> InvokeAsync(GetListenerArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetListenerResult>("oci:NetworkLoadBalancer/getListener:getListener", args ?? new GetListenerArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Listener resource in Oracle Cloud Infrastructure Network Load Balancer service.
        /// 
        /// Retrieves listener properties associated with a given network load balancer and listener name.
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
        ///     var testListener = Oci.NetworkLoadBalancer.GetListener.Invoke(new()
        ///     {
        ///         ListenerName = testListenerOciNetworkLoadBalancerListener.Name,
        ///         NetworkLoadBalancerId = testNetworkLoadBalancer.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetListenerResult> Invoke(GetListenerInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetListenerResult>("oci:NetworkLoadBalancer/getListener:getListener", args ?? new GetListenerInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Listener resource in Oracle Cloud Infrastructure Network Load Balancer service.
        /// 
        /// Retrieves listener properties associated with a given network load balancer and listener name.
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
        ///     var testListener = Oci.NetworkLoadBalancer.GetListener.Invoke(new()
        ///     {
        ///         ListenerName = testListenerOciNetworkLoadBalancerListener.Name,
        ///         NetworkLoadBalancerId = testNetworkLoadBalancer.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetListenerResult> Invoke(GetListenerInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetListenerResult>("oci:NetworkLoadBalancer/getListener:getListener", args ?? new GetListenerInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetListenerArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the listener to get.  Example: `example_listener`
        /// </summary>
        [Input("listenerName", required: true)]
        public string ListenerName { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
        /// </summary>
        [Input("networkLoadBalancerId", required: true)]
        public string NetworkLoadBalancerId { get; set; } = null!;

        public GetListenerArgs()
        {
        }
        public static new GetListenerArgs Empty => new GetListenerArgs();
    }

    public sealed class GetListenerInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the listener to get.  Example: `example_listener`
        /// </summary>
        [Input("listenerName", required: true)]
        public Input<string> ListenerName { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
        /// </summary>
        [Input("networkLoadBalancerId", required: true)]
        public Input<string> NetworkLoadBalancerId { get; set; } = null!;

        public GetListenerInvokeArgs()
        {
        }
        public static new GetListenerInvokeArgs Empty => new GetListenerInvokeArgs();
    }


    [OutputType]
    public sealed class GetListenerResult
    {
        /// <summary>
        /// The name of the associated backend set.  Example: `example_backend_set`
        /// </summary>
        public readonly string DefaultBackendSetName;
        public readonly string Id;
        /// <summary>
        /// IP version associated with the listener.
        /// </summary>
        public readonly string IpVersion;
        /// <summary>
        /// Property to enable/disable PPv2 feature for this listener.
        /// </summary>
        public readonly bool IsPpv2enabled;
        /// <summary>
        /// The duration for L3IP idle timeout in seconds. Example: `200`
        /// </summary>
        public readonly int L3ipIdleTimeout;
        public readonly string ListenerName;
        /// <summary>
        /// A friendly name for the listener. It must be unique and it cannot be changed.  Example: `example_listener`
        /// </summary>
        public readonly string Name;
        public readonly string NetworkLoadBalancerId;
        /// <summary>
        /// The communication port for the listener.  Example: `80`
        /// </summary>
        public readonly int Port;
        /// <summary>
        /// The protocol on which the listener accepts connection requests. For public network load balancers, ANY protocol refers to TCP/UDP with the wildcard port. For private network load balancers, ANY protocol refers to TCP/UDP/ICMP (note that ICMP requires isPreserveSourceDestination to be set to true). "ListNetworkLoadBalancersProtocols" API is deprecated and it will not return the updated values. Use the allowed values for the protocol instead.  Example: `TCP`
        /// </summary>
        public readonly string Protocol;
        /// <summary>
        /// The duration for TCP idle timeout in seconds. Example: `300`
        /// </summary>
        public readonly int TcpIdleTimeout;
        /// <summary>
        /// The duration for UDP idle timeout in seconds. Example: `120`
        /// </summary>
        public readonly int UdpIdleTimeout;

        [OutputConstructor]
        private GetListenerResult(
            string defaultBackendSetName,

            string id,

            string ipVersion,

            bool isPpv2enabled,

            int l3ipIdleTimeout,

            string listenerName,

            string name,

            string networkLoadBalancerId,

            int port,

            string protocol,

            int tcpIdleTimeout,

            int udpIdleTimeout)
        {
            DefaultBackendSetName = defaultBackendSetName;
            Id = id;
            IpVersion = ipVersion;
            IsPpv2enabled = isPpv2enabled;
            L3ipIdleTimeout = l3ipIdleTimeout;
            ListenerName = listenerName;
            Name = name;
            NetworkLoadBalancerId = networkLoadBalancerId;
            Port = port;
            Protocol = protocol;
            TcpIdleTimeout = tcpIdleTimeout;
            UdpIdleTimeout = udpIdleTimeout;
        }
    }
}
