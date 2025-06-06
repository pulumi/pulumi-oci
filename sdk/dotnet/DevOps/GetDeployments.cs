// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps
{
    public static class GetDeployments
    {
        /// <summary>
        /// This data source provides the list of Deployments in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Returns a list of deployments.
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
        ///     var testDeployments = Oci.DevOps.GetDeployments.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DeployPipelineId = testDeployPipeline.Id,
        ///         DisplayName = deploymentDisplayName,
        ///         Id = deploymentId,
        ///         ProjectId = testProject.Id,
        ///         State = deploymentState,
        ///         TimeCreatedGreaterThanOrEqualTo = deploymentTimeCreatedGreaterThanOrEqualTo,
        ///         TimeCreatedLessThan = deploymentTimeCreatedLessThan,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetDeploymentsResult> InvokeAsync(GetDeploymentsArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetDeploymentsResult>("oci:DevOps/getDeployments:getDeployments", args ?? new GetDeploymentsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Deployments in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Returns a list of deployments.
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
        ///     var testDeployments = Oci.DevOps.GetDeployments.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DeployPipelineId = testDeployPipeline.Id,
        ///         DisplayName = deploymentDisplayName,
        ///         Id = deploymentId,
        ///         ProjectId = testProject.Id,
        ///         State = deploymentState,
        ///         TimeCreatedGreaterThanOrEqualTo = deploymentTimeCreatedGreaterThanOrEqualTo,
        ///         TimeCreatedLessThan = deploymentTimeCreatedLessThan,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDeploymentsResult> Invoke(GetDeploymentsInvokeArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetDeploymentsResult>("oci:DevOps/getDeployments:getDeployments", args ?? new GetDeploymentsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Deployments in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Returns a list of deployments.
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
        ///     var testDeployments = Oci.DevOps.GetDeployments.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DeployPipelineId = testDeployPipeline.Id,
        ///         DisplayName = deploymentDisplayName,
        ///         Id = deploymentId,
        ///         ProjectId = testProject.Id,
        ///         State = deploymentState,
        ///         TimeCreatedGreaterThanOrEqualTo = deploymentTimeCreatedGreaterThanOrEqualTo,
        ///         TimeCreatedLessThan = deploymentTimeCreatedLessThan,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDeploymentsResult> Invoke(GetDeploymentsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetDeploymentsResult>("oci:DevOps/getDeployments:getDeployments", args ?? new GetDeploymentsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDeploymentsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId")]
        public string? CompartmentId { get; set; }

        /// <summary>
        /// The ID of the parent pipeline.
        /// </summary>
        [Input("deployPipelineId")]
        public string? DeployPipelineId { get; set; }

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetDeploymentsFilterArgs>? _filters;
        public List<Inputs.GetDeploymentsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetDeploymentsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Unique identifier or OCID for listing a single resource by ID.
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

        /// <summary>
        /// unique project identifier
        /// </summary>
        [Input("projectId")]
        public string? ProjectId { get; set; }

        /// <summary>
        /// A filter to return only Deployments that matches the given lifecycleState.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        /// <summary>
        /// Search for DevOps resources that were created after a specific date. Specifying this parameter corresponding to `timeCreatedGreaterThanOrEqualTo` parameter will retrieve all security assessments created after the specified created date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        /// </summary>
        [Input("timeCreatedGreaterThanOrEqualTo")]
        public string? TimeCreatedGreaterThanOrEqualTo { get; set; }

        /// <summary>
        /// Search for DevOps resources that were created before a specific date. Specifying this parameter corresponding to `timeCreatedLessThan` parameter will retrieve all assessments created before the specified created date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        /// </summary>
        [Input("timeCreatedLessThan")]
        public string? TimeCreatedLessThan { get; set; }

        public GetDeploymentsArgs()
        {
        }
        public static new GetDeploymentsArgs Empty => new GetDeploymentsArgs();
    }

    public sealed class GetDeploymentsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// The ID of the parent pipeline.
        /// </summary>
        [Input("deployPipelineId")]
        public Input<string>? DeployPipelineId { get; set; }

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetDeploymentsFilterInputArgs>? _filters;
        public InputList<Inputs.GetDeploymentsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetDeploymentsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Unique identifier or OCID for listing a single resource by ID.
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        /// <summary>
        /// unique project identifier
        /// </summary>
        [Input("projectId")]
        public Input<string>? ProjectId { get; set; }

        /// <summary>
        /// A filter to return only Deployments that matches the given lifecycleState.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// Search for DevOps resources that were created after a specific date. Specifying this parameter corresponding to `timeCreatedGreaterThanOrEqualTo` parameter will retrieve all security assessments created after the specified created date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        /// </summary>
        [Input("timeCreatedGreaterThanOrEqualTo")]
        public Input<string>? TimeCreatedGreaterThanOrEqualTo { get; set; }

        /// <summary>
        /// Search for DevOps resources that were created before a specific date. Specifying this parameter corresponding to `timeCreatedLessThan` parameter will retrieve all assessments created before the specified created date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        /// </summary>
        [Input("timeCreatedLessThan")]
        public Input<string>? TimeCreatedLessThan { get; set; }

        public GetDeploymentsInvokeArgs()
        {
        }
        public static new GetDeploymentsInvokeArgs Empty => new GetDeploymentsInvokeArgs();
    }


    [OutputType]
    public sealed class GetDeploymentsResult
    {
        /// <summary>
        /// The OCID of a compartment.
        /// </summary>
        public readonly string? CompartmentId;
        /// <summary>
        /// The OCID of a pipeline.
        /// </summary>
        public readonly string? DeployPipelineId;
        /// <summary>
        /// The list of deployment_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionResult> DeploymentCollections;
        /// <summary>
        /// Deployment identifier which can be renamed and is not necessarily unique. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetDeploymentsFilterResult> Filters;
        /// <summary>
        /// Unique identifier that is immutable on creation.
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// The OCID of a project.
        /// </summary>
        public readonly string? ProjectId;
        /// <summary>
        /// The current state of the deployment.
        /// </summary>
        public readonly string? State;
        public readonly string? TimeCreatedGreaterThanOrEqualTo;
        public readonly string? TimeCreatedLessThan;

        [OutputConstructor]
        private GetDeploymentsResult(
            string? compartmentId,

            string? deployPipelineId,

            ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionResult> deploymentCollections,

            string? displayName,

            ImmutableArray<Outputs.GetDeploymentsFilterResult> filters,

            string? id,

            string? projectId,

            string? state,

            string? timeCreatedGreaterThanOrEqualTo,

            string? timeCreatedLessThan)
        {
            CompartmentId = compartmentId;
            DeployPipelineId = deployPipelineId;
            DeploymentCollections = deploymentCollections;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            ProjectId = projectId;
            State = state;
            TimeCreatedGreaterThanOrEqualTo = timeCreatedGreaterThanOrEqualTo;
            TimeCreatedLessThan = timeCreatedLessThan;
        }
    }
}
