// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LoadBalancer
{
    public static class GetSslCipherSuite
    {
        /// <summary>
        /// This data source provides details about a specific Ssl Cipher Suite resource in Oracle Cloud Infrastructure Load Balancer service.
        /// 
        /// Gets the specified SSL cipher suite's configuration information.
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
        ///         var testSslCipherSuite = Output.Create(Oci.LoadBalancer.GetSslCipherSuite.InvokeAsync(new Oci.LoadBalancer.GetSslCipherSuiteArgs
        ///         {
        ///             Name = @var.Ssl_cipher_suite_name,
        ///             LoadBalancerId = oci_load_balancer_load_balancer.Test_load_balancer.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetSslCipherSuiteResult> InvokeAsync(GetSslCipherSuiteArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetSslCipherSuiteResult>("oci:LoadBalancer/getSslCipherSuite:getSslCipherSuite", args ?? new GetSslCipherSuiteArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Ssl Cipher Suite resource in Oracle Cloud Infrastructure Load Balancer service.
        /// 
        /// Gets the specified SSL cipher suite's configuration information.
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
        ///         var testSslCipherSuite = Output.Create(Oci.LoadBalancer.GetSslCipherSuite.InvokeAsync(new Oci.LoadBalancer.GetSslCipherSuiteArgs
        ///         {
        ///             Name = @var.Ssl_cipher_suite_name,
        ///             LoadBalancerId = oci_load_balancer_load_balancer.Test_load_balancer.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetSslCipherSuiteResult> Invoke(GetSslCipherSuiteInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetSslCipherSuiteResult>("oci:LoadBalancer/getSslCipherSuite:getSslCipherSuite", args ?? new GetSslCipherSuiteInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetSslCipherSuiteArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated load balancer.
        /// </summary>
        [Input("loadBalancerId", required: true)]
        public string LoadBalancerId { get; set; } = null!;

        /// <summary>
        /// The name of the SSL cipher suite to retrieve.
        /// </summary>
        [Input("name", required: true)]
        public string Name { get; set; } = null!;

        public GetSslCipherSuiteArgs()
        {
        }
    }

    public sealed class GetSslCipherSuiteInvokeArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated load balancer.
        /// </summary>
        [Input("loadBalancerId", required: true)]
        public Input<string> LoadBalancerId { get; set; } = null!;

        /// <summary>
        /// The name of the SSL cipher suite to retrieve.
        /// </summary>
        [Input("name", required: true)]
        public Input<string> Name { get; set; } = null!;

        public GetSslCipherSuiteInvokeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetSslCipherSuiteResult
    {
        /// <summary>
        /// A list of SSL ciphers the load balancer must support for HTTPS or SSL connections.
        /// </summary>
        public readonly ImmutableArray<string> Ciphers;
        public readonly string Id;
        public readonly string LoadBalancerId;
        /// <summary>
        /// A friendly name for the SSL cipher suite. It must be unique and it cannot be changed.
        /// </summary>
        public readonly string Name;
        public readonly string State;

        [OutputConstructor]
        private GetSslCipherSuiteResult(
            ImmutableArray<string> ciphers,

            string id,

            string loadBalancerId,

            string name,

            string state)
        {
            Ciphers = ciphers;
            Id = id;
            LoadBalancerId = loadBalancerId;
            Name = name;
            State = state;
        }
    }
}
