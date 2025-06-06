// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.NetworkLoadBalancer
{
    public static class GetListeners
    {
        /// <summary>
        /// This data source provides the list of Listeners in Oracle Cloud Infrastructure Network Load Balancer service.
        /// 
        /// Lists all listeners associated with a given network load balancer.
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
        ///     var testListeners = Oci.NetworkLoadBalancer.GetListeners.Invoke(new()
        ///     {
        ///         NetworkLoadBalancerId = testNetworkLoadBalancer.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetListenersResult> InvokeAsync(GetListenersArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetListenersResult>("oci:NetworkLoadBalancer/getListeners:getListeners", args ?? new GetListenersArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Listeners in Oracle Cloud Infrastructure Network Load Balancer service.
        /// 
        /// Lists all listeners associated with a given network load balancer.
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
        ///     var testListeners = Oci.NetworkLoadBalancer.GetListeners.Invoke(new()
        ///     {
        ///         NetworkLoadBalancerId = testNetworkLoadBalancer.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetListenersResult> Invoke(GetListenersInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetListenersResult>("oci:NetworkLoadBalancer/getListeners:getListeners", args ?? new GetListenersInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Listeners in Oracle Cloud Infrastructure Network Load Balancer service.
        /// 
        /// Lists all listeners associated with a given network load balancer.
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
        ///     var testListeners = Oci.NetworkLoadBalancer.GetListeners.Invoke(new()
        ///     {
        ///         NetworkLoadBalancerId = testNetworkLoadBalancer.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetListenersResult> Invoke(GetListenersInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetListenersResult>("oci:NetworkLoadBalancer/getListeners:getListeners", args ?? new GetListenersInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetListenersArgs : global::Pulumi.InvokeArgs
    {
        [Input("filters")]
        private List<Inputs.GetListenersFilterArgs>? _filters;
        public List<Inputs.GetListenersFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetListenersFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
        /// </summary>
        [Input("networkLoadBalancerId", required: true)]
        public string NetworkLoadBalancerId { get; set; } = null!;

        public GetListenersArgs()
        {
        }
        public static new GetListenersArgs Empty => new GetListenersArgs();
    }

    public sealed class GetListenersInvokeArgs : global::Pulumi.InvokeArgs
    {
        [Input("filters")]
        private InputList<Inputs.GetListenersFilterInputArgs>? _filters;
        public InputList<Inputs.GetListenersFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetListenersFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
        /// </summary>
        [Input("networkLoadBalancerId", required: true)]
        public Input<string> NetworkLoadBalancerId { get; set; } = null!;

        public GetListenersInvokeArgs()
        {
        }
        public static new GetListenersInvokeArgs Empty => new GetListenersInvokeArgs();
    }


    [OutputType]
    public sealed class GetListenersResult
    {
        public readonly ImmutableArray<Outputs.GetListenersFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of listener_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetListenersListenerCollectionResult> ListenerCollections;
        public readonly string NetworkLoadBalancerId;

        [OutputConstructor]
        private GetListenersResult(
            ImmutableArray<Outputs.GetListenersFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetListenersListenerCollectionResult> listenerCollections,

            string networkLoadBalancerId)
        {
            Filters = filters;
            Id = id;
            ListenerCollections = listenerCollections;
            NetworkLoadBalancerId = networkLoadBalancerId;
        }
    }
}
