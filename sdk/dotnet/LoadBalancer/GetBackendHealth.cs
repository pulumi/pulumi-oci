// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LoadBalancer
{
    public static class GetBackendHealth
    {
        /// <summary>
        /// This data source provides details about a specific Backend Health resource in Oracle Cloud Infrastructure Load Balancer service.
        /// 
        /// Gets the current health status of the specified backend server.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testBackendHealth = Oci.LoadBalancer.GetBackendHealth.Invoke(new()
        ///     {
        ///         BackendName = oci_load_balancer_backend.Test_backend.Name,
        ///         BackendSetName = oci_load_balancer_backend_set.Test_backend_set.Name,
        ///         LoadBalancerId = oci_load_balancer_load_balancer.Test_load_balancer.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetBackendHealthResult> InvokeAsync(GetBackendHealthArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetBackendHealthResult>("oci:LoadBalancer/getBackendHealth:getBackendHealth", args ?? new GetBackendHealthArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Backend Health resource in Oracle Cloud Infrastructure Load Balancer service.
        /// 
        /// Gets the current health status of the specified backend server.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testBackendHealth = Oci.LoadBalancer.GetBackendHealth.Invoke(new()
        ///     {
        ///         BackendName = oci_load_balancer_backend.Test_backend.Name,
        ///         BackendSetName = oci_load_balancer_backend_set.Test_backend_set.Name,
        ///         LoadBalancerId = oci_load_balancer_load_balancer.Test_load_balancer.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetBackendHealthResult> Invoke(GetBackendHealthInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetBackendHealthResult>("oci:LoadBalancer/getBackendHealth:getBackendHealth", args ?? new GetBackendHealthInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetBackendHealthArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The IP address and port of the backend server to retrieve the health status for.  Example: `10.0.0.3:8080`
        /// </summary>
        [Input("backendName", required: true)]
        public string BackendName { get; set; } = null!;

        /// <summary>
        /// The name of the backend set associated with the backend server to retrieve the health status for.  Example: `example_backend_set`
        /// </summary>
        [Input("backendSetName", required: true)]
        public string BackendSetName { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the backend server health status to be retrieved.
        /// </summary>
        [Input("loadBalancerId", required: true)]
        public string LoadBalancerId { get; set; } = null!;

        public GetBackendHealthArgs()
        {
        }
        public static new GetBackendHealthArgs Empty => new GetBackendHealthArgs();
    }

    public sealed class GetBackendHealthInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The IP address and port of the backend server to retrieve the health status for.  Example: `10.0.0.3:8080`
        /// </summary>
        [Input("backendName", required: true)]
        public Input<string> BackendName { get; set; } = null!;

        /// <summary>
        /// The name of the backend set associated with the backend server to retrieve the health status for.  Example: `example_backend_set`
        /// </summary>
        [Input("backendSetName", required: true)]
        public Input<string> BackendSetName { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the backend server health status to be retrieved.
        /// </summary>
        [Input("loadBalancerId", required: true)]
        public Input<string> LoadBalancerId { get; set; } = null!;

        public GetBackendHealthInvokeArgs()
        {
        }
        public static new GetBackendHealthInvokeArgs Empty => new GetBackendHealthInvokeArgs();
    }


    [OutputType]
    public sealed class GetBackendHealthResult
    {
        public readonly string BackendName;
        public readonly string BackendSetName;
        /// <summary>
        /// A list of the most recent health check results returned for the specified backend server.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBackendHealthHealthCheckResultResult> HealthCheckResults;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string LoadBalancerId;
        /// <summary>
        /// The general health status of the specified backend server as reported by the primary and standby load balancers.
        /// *   **OK:** Both health checks returned `OK`.
        /// *   **WARNING:** One health check returned `OK` and one did not.
        /// *   **CRITICAL:** Neither health check returned `OK`.
        /// *   **UNKNOWN:** One or both health checks returned `UNKNOWN`, or the system was unable to retrieve metrics at this time.
        /// </summary>
        public readonly string Status;

        [OutputConstructor]
        private GetBackendHealthResult(
            string backendName,

            string backendSetName,

            ImmutableArray<Outputs.GetBackendHealthHealthCheckResultResult> healthCheckResults,

            string id,

            string loadBalancerId,

            string status)
        {
            BackendName = backendName;
            BackendSetName = backendSetName;
            HealthCheckResults = healthCheckResults;
            Id = id;
            LoadBalancerId = loadBalancerId;
            Status = status;
        }
    }
}