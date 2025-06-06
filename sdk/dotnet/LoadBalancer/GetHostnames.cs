// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LoadBalancer
{
    public static class GetHostnames
    {
        /// <summary>
        /// This data source provides the list of Hostnames in Oracle Cloud Infrastructure Load Balancer service.
        /// 
        /// Lists all hostname resources associated with the specified load balancer.
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
        ///     var testHostnames = Oci.LoadBalancer.GetHostnames.Invoke(new()
        ///     {
        ///         LoadBalancerId = testLoadBalancer.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetHostnamesResult> InvokeAsync(GetHostnamesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetHostnamesResult>("oci:LoadBalancer/getHostnames:getHostnames", args ?? new GetHostnamesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Hostnames in Oracle Cloud Infrastructure Load Balancer service.
        /// 
        /// Lists all hostname resources associated with the specified load balancer.
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
        ///     var testHostnames = Oci.LoadBalancer.GetHostnames.Invoke(new()
        ///     {
        ///         LoadBalancerId = testLoadBalancer.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetHostnamesResult> Invoke(GetHostnamesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetHostnamesResult>("oci:LoadBalancer/getHostnames:getHostnames", args ?? new GetHostnamesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Hostnames in Oracle Cloud Infrastructure Load Balancer service.
        /// 
        /// Lists all hostname resources associated with the specified load balancer.
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
        ///     var testHostnames = Oci.LoadBalancer.GetHostnames.Invoke(new()
        ///     {
        ///         LoadBalancerId = testLoadBalancer.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetHostnamesResult> Invoke(GetHostnamesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetHostnamesResult>("oci:LoadBalancer/getHostnames:getHostnames", args ?? new GetHostnamesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetHostnamesArgs : global::Pulumi.InvokeArgs
    {
        [Input("filters")]
        private List<Inputs.GetHostnamesFilterArgs>? _filters;
        public List<Inputs.GetHostnamesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetHostnamesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the hostnames to retrieve.
        /// </summary>
        [Input("loadBalancerId", required: true)]
        public string LoadBalancerId { get; set; } = null!;

        public GetHostnamesArgs()
        {
        }
        public static new GetHostnamesArgs Empty => new GetHostnamesArgs();
    }

    public sealed class GetHostnamesInvokeArgs : global::Pulumi.InvokeArgs
    {
        [Input("filters")]
        private InputList<Inputs.GetHostnamesFilterInputArgs>? _filters;
        public InputList<Inputs.GetHostnamesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetHostnamesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the hostnames to retrieve.
        /// </summary>
        [Input("loadBalancerId", required: true)]
        public Input<string> LoadBalancerId { get; set; } = null!;

        public GetHostnamesInvokeArgs()
        {
        }
        public static new GetHostnamesInvokeArgs Empty => new GetHostnamesInvokeArgs();
    }


    [OutputType]
    public sealed class GetHostnamesResult
    {
        public readonly ImmutableArray<Outputs.GetHostnamesFilterResult> Filters;
        /// <summary>
        /// The list of hostnames.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetHostnamesHostnameResult> Hostnames;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string LoadBalancerId;

        [OutputConstructor]
        private GetHostnamesResult(
            ImmutableArray<Outputs.GetHostnamesFilterResult> filters,

            ImmutableArray<Outputs.GetHostnamesHostnameResult> hostnames,

            string id,

            string loadBalancerId)
        {
            Filters = filters;
            Hostnames = hostnames;
            Id = id;
            LoadBalancerId = loadBalancerId;
        }
    }
}
