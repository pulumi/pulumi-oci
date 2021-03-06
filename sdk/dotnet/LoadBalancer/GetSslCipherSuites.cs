// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LoadBalancer
{
    public static class GetSslCipherSuites
    {
        /// <summary>
        /// This data source provides the list of Ssl Cipher Suites in Oracle Cloud Infrastructure Load Balancer service.
        /// 
        /// Lists all SSL cipher suites associated with the specified load balancer.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testSslCipherSuites = Output.Create(Oci.LoadBalancer.GetSslCipherSuites.InvokeAsync(new Oci.LoadBalancer.GetSslCipherSuitesArgs
        ///         {
        ///             LoadBalancerId = oci_load_balancer_load_balancer.Test_load_balancer.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetSslCipherSuitesResult> InvokeAsync(GetSslCipherSuitesArgs? args = null, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetSslCipherSuitesResult>("oci:LoadBalancer/getSslCipherSuites:getSslCipherSuites", args ?? new GetSslCipherSuitesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Ssl Cipher Suites in Oracle Cloud Infrastructure Load Balancer service.
        /// 
        /// Lists all SSL cipher suites associated with the specified load balancer.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testSslCipherSuites = Output.Create(Oci.LoadBalancer.GetSslCipherSuites.InvokeAsync(new Oci.LoadBalancer.GetSslCipherSuitesArgs
        ///         {
        ///             LoadBalancerId = oci_load_balancer_load_balancer.Test_load_balancer.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetSslCipherSuitesResult> Invoke(GetSslCipherSuitesInvokeArgs? args = null, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetSslCipherSuitesResult>("oci:LoadBalancer/getSslCipherSuites:getSslCipherSuites", args ?? new GetSslCipherSuitesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetSslCipherSuitesArgs : Pulumi.InvokeArgs
    {
        [Input("filters")]
        private List<Inputs.GetSslCipherSuitesFilterArgs>? _filters;
        public List<Inputs.GetSslCipherSuitesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetSslCipherSuitesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated load balancer.
        /// </summary>
        [Input("loadBalancerId")]
        public string? LoadBalancerId { get; set; }

        public GetSslCipherSuitesArgs()
        {
        }
    }

    public sealed class GetSslCipherSuitesInvokeArgs : Pulumi.InvokeArgs
    {
        [Input("filters")]
        private InputList<Inputs.GetSslCipherSuitesFilterInputArgs>? _filters;
        public InputList<Inputs.GetSslCipherSuitesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetSslCipherSuitesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated load balancer.
        /// </summary>
        [Input("loadBalancerId")]
        public Input<string>? LoadBalancerId { get; set; }

        public GetSslCipherSuitesInvokeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetSslCipherSuitesResult
    {
        public readonly ImmutableArray<Outputs.GetSslCipherSuitesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string? LoadBalancerId;
        /// <summary>
        /// The list of ssl_cipher_suites.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSslCipherSuitesSslCipherSuiteResult> SslCipherSuites;

        [OutputConstructor]
        private GetSslCipherSuitesResult(
            ImmutableArray<Outputs.GetSslCipherSuitesFilterResult> filters,

            string id,

            string? loadBalancerId,

            ImmutableArray<Outputs.GetSslCipherSuitesSslCipherSuiteResult> sslCipherSuites)
        {
            Filters = filters;
            Id = id;
            LoadBalancerId = loadBalancerId;
            SslCipherSuites = sslCipherSuites;
        }
    }
}
