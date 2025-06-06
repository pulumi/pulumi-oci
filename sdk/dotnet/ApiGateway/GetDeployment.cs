// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway
{
    public static class GetDeployment
    {
        /// <summary>
        /// This data source provides details about a specific Deployment resource in Oracle Cloud Infrastructure API Gateway service.
        /// 
        /// Gets a deployment by identifier.
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
        ///     var testDeployment = Oci.ApiGateway.GetDeployment.Invoke(new()
        ///     {
        ///         DeploymentId = testDeploymentOciApigatewayDeployment.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetDeploymentResult> InvokeAsync(GetDeploymentArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetDeploymentResult>("oci:ApiGateway/getDeployment:getDeployment", args ?? new GetDeploymentArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Deployment resource in Oracle Cloud Infrastructure API Gateway service.
        /// 
        /// Gets a deployment by identifier.
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
        ///     var testDeployment = Oci.ApiGateway.GetDeployment.Invoke(new()
        ///     {
        ///         DeploymentId = testDeploymentOciApigatewayDeployment.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDeploymentResult> Invoke(GetDeploymentInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetDeploymentResult>("oci:ApiGateway/getDeployment:getDeployment", args ?? new GetDeploymentInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Deployment resource in Oracle Cloud Infrastructure API Gateway service.
        /// 
        /// Gets a deployment by identifier.
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
        ///     var testDeployment = Oci.ApiGateway.GetDeployment.Invoke(new()
        ///     {
        ///         DeploymentId = testDeploymentOciApigatewayDeployment.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDeploymentResult> Invoke(GetDeploymentInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetDeploymentResult>("oci:ApiGateway/getDeployment:getDeployment", args ?? new GetDeploymentInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDeploymentArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ocid of the deployment.
        /// </summary>
        [Input("deploymentId", required: true)]
        public string DeploymentId { get; set; } = null!;

        public GetDeploymentArgs()
        {
        }
        public static new GetDeploymentArgs Empty => new GetDeploymentArgs();
    }

    public sealed class GetDeploymentInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ocid of the deployment.
        /// </summary>
        [Input("deploymentId", required: true)]
        public Input<string> DeploymentId { get; set; } = null!;

        public GetDeploymentInvokeArgs()
        {
        }
        public static new GetDeploymentInvokeArgs Empty => new GetDeploymentInvokeArgs();
    }


    [OutputType]
    public sealed class GetDeploymentResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        public readonly string DeploymentId;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The endpoint to access this deployment on the gateway.
        /// </summary>
        public readonly string Endpoint;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
        /// </summary>
        public readonly string GatewayId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// A path on which to deploy all routes contained in the API deployment specification. For more information, see [Deploying an API on an API Gateway by Creating an API Deployment](https://docs.cloud.oracle.com/iaas/Content/APIGateway/Tasks/apigatewaycreatingdeployment.htm).
        /// </summary>
        public readonly string PathPrefix;
        /// <summary>
        /// The logical configuration of the API exposed by a deployment.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentSpecificationResult> Specifications;
        /// <summary>
        /// The current state of the deployment.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The time this resource was created. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time this resource was last updated. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetDeploymentResult(
            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string deploymentId,

            string displayName,

            string endpoint,

            ImmutableDictionary<string, string> freeformTags,

            string gatewayId,

            string id,

            string lifecycleDetails,

            string pathPrefix,

            ImmutableArray<Outputs.GetDeploymentSpecificationResult> specifications,

            string state,

            string timeCreated,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DeploymentId = deploymentId;
            DisplayName = displayName;
            Endpoint = endpoint;
            FreeformTags = freeformTags;
            GatewayId = gatewayId;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            PathPrefix = pathPrefix;
            Specifications = specifications;
            State = state;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
