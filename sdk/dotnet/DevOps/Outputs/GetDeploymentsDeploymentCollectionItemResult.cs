// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Outputs
{

    [OutputType]
    public sealed class GetDeploymentsDeploymentCollectionItemResult
    {
        /// <summary>
        /// The OCID of the compartment in which to list resources.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// Specifies the list of artifact override arguments at the time of deployment.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionItemDeployArtifactOverrideArgumentResult> DeployArtifactOverrideArguments;
        /// <summary>
        /// List of all artifacts used in the pipeline.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionItemDeployPipelineArtifactResult> DeployPipelineArtifacts;
        /// <summary>
        /// List of all environments used in the pipeline.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionItemDeployPipelineEnvironmentResult> DeployPipelineEnvironments;
        /// <summary>
        /// The ID of the parent pipeline.
        /// </summary>
        public readonly string DeployPipelineId;
        /// <summary>
        /// The OCID of the stage.
        /// </summary>
        public readonly string DeployStageId;
        /// <summary>
        /// Specifies the list of arguments to be overriden per Stage at the time of deployment.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionItemDeployStageOverrideArgumentResult> DeployStageOverrideArguments;
        /// <summary>
        /// Specifies list of arguments passed along with the deployment.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionItemDeploymentArgumentResult> DeploymentArguments;
        /// <summary>
        /// The execution progress details of a deployment.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionItemDeploymentExecutionProgressResult> DeploymentExecutionProgresses;
        /// <summary>
        /// Specifies type of Deployment
        /// </summary>
        public readonly string DeploymentType;
        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// Unique identifier or OCID for listing a single resource by ID.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// Specifies the OCID of the previous deployment to be redeployed.
        /// </summary>
        public readonly string PreviousDeploymentId;
        /// <summary>
        /// unique project identifier
        /// </summary>
        public readonly string ProjectId;
        /// <summary>
        /// A filter to return only Deployments that matches the given lifecycleState.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// Time the deployment was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// Time the deployment was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        /// </summary>
        public readonly string TimeUpdated;
        public readonly bool TriggerNewDevopsDeployment;

        [OutputConstructor]
        private GetDeploymentsDeploymentCollectionItemResult(
            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionItemDeployArtifactOverrideArgumentResult> deployArtifactOverrideArguments,

            ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionItemDeployPipelineArtifactResult> deployPipelineArtifacts,

            ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionItemDeployPipelineEnvironmentResult> deployPipelineEnvironments,

            string deployPipelineId,

            string deployStageId,

            ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionItemDeployStageOverrideArgumentResult> deployStageOverrideArguments,

            ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionItemDeploymentArgumentResult> deploymentArguments,

            ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionItemDeploymentExecutionProgressResult> deploymentExecutionProgresses,

            string deploymentType,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string lifecycleDetails,

            string previousDeploymentId,

            string projectId,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated,

            bool triggerNewDevopsDeployment)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DeployArtifactOverrideArguments = deployArtifactOverrideArguments;
            DeployPipelineArtifacts = deployPipelineArtifacts;
            DeployPipelineEnvironments = deployPipelineEnvironments;
            DeployPipelineId = deployPipelineId;
            DeployStageId = deployStageId;
            DeployStageOverrideArguments = deployStageOverrideArguments;
            DeploymentArguments = deploymentArguments;
            DeploymentExecutionProgresses = deploymentExecutionProgresses;
            DeploymentType = deploymentType;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            PreviousDeploymentId = previousDeploymentId;
            ProjectId = projectId;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            TriggerNewDevopsDeployment = triggerNewDevopsDeployment;
        }
    }
}
