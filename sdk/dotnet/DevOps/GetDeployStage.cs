// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps
{
    public static class GetDeployStage
    {
        /// <summary>
        /// This data source provides details about a specific Deploy Stage resource in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Retrieves a deployment stage by identifier.
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
        ///     var testDeployStage = Oci.DevOps.GetDeployStage.Invoke(new()
        ///     {
        ///         DeployStageId = oci_devops_deploy_stage.Test_deploy_stage.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetDeployStageResult> InvokeAsync(GetDeployStageArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetDeployStageResult>("oci:DevOps/getDeployStage:getDeployStage", args ?? new GetDeployStageArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Deploy Stage resource in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Retrieves a deployment stage by identifier.
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
        ///     var testDeployStage = Oci.DevOps.GetDeployStage.Invoke(new()
        ///     {
        ///         DeployStageId = oci_devops_deploy_stage.Test_deploy_stage.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetDeployStageResult> Invoke(GetDeployStageInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetDeployStageResult>("oci:DevOps/getDeployStage:getDeployStage", args ?? new GetDeployStageInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDeployStageArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Unique stage identifier.
        /// </summary>
        [Input("deployStageId", required: true)]
        public string DeployStageId { get; set; } = null!;

        public GetDeployStageArgs()
        {
        }
        public static new GetDeployStageArgs Empty => new GetDeployStageArgs();
    }

    public sealed class GetDeployStageInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Unique stage identifier.
        /// </summary>
        [Input("deployStageId", required: true)]
        public Input<string> DeployStageId { get; set; } = null!;

        public GetDeployStageInvokeArgs()
        {
        }
        public static new GetDeployStageInvokeArgs Empty => new GetDeployStageInvokeArgs();
    }


    [OutputType]
    public sealed class GetDeployStageResult
    {
        /// <summary>
        /// Specifies the approval policy.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeployStageApprovalPolicyResult> ApprovalPolicies;
        /// <summary>
        /// Collection of backend environment IP addresses.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeployStageBlueBackendIpResult> BlueBackendIps;
        /// <summary>
        /// Specifies the required blue green release strategy for OKE deployment.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeployStageBlueGreenStrategyResult> BlueGreenStrategies;
        /// <summary>
        /// Specifies the required canary release strategy for OKE deployment.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeployStageCanaryStrategyResult> CanaryStrategies;
        /// <summary>
        /// The OCID of a compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The OCID of the upstream compute instance group blue-green deployment stage in this pipeline.
        /// </summary>
        public readonly string ComputeInstanceGroupBlueGreenDeploymentDeployStageId;
        /// <summary>
        /// The OCID of an upstream compute instance group canary deployment stage ID in this pipeline.
        /// </summary>
        public readonly string ComputeInstanceGroupCanaryDeployStageId;
        /// <summary>
        /// A compute instance group canary traffic shift stage OCID for load balancer.
        /// </summary>
        public readonly string ComputeInstanceGroupCanaryTrafficShiftDeployStageId;
        /// <summary>
        /// A compute instance group environment OCID for rolling deployment.
        /// </summary>
        public readonly string ComputeInstanceGroupDeployEnvironmentId;
        /// <summary>
        /// User provided key and value pair configuration, which is assigned through constants or parameter.
        /// </summary>
        public readonly ImmutableDictionary<string, object> Config;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// Optional artifact OCID. The artifact will be included in the body for the function invocation during the stage's execution. If the DeployArtifact.argumentSubstituitionMode is set to SUBSTITUTE_PLACEHOLDERS, then the pipeline parameter values will be used to replace the placeholders in the artifact content.
        /// </summary>
        public readonly string DeployArtifactId;
        /// <summary>
        /// The list of file artifact OCIDs to deploy.
        /// </summary>
        public readonly ImmutableArray<string> DeployArtifactIds;
        /// <summary>
        /// First compute instance group environment OCID for deployment.
        /// </summary>
        public readonly string DeployEnvironmentIdA;
        /// <summary>
        /// Second compute instance group environment OCID for deployment.
        /// </summary>
        public readonly string DeployEnvironmentIdB;
        /// <summary>
        /// The OCID of a pipeline.
        /// </summary>
        public readonly string DeployPipelineId;
        public readonly string DeployStageId;
        /// <summary>
        /// Collection containing the predecessors of a stage.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeployStageDeployStagePredecessorCollectionResult> DeployStagePredecessorCollections;
        /// <summary>
        /// Deployment stage type.
        /// </summary>
        public readonly string DeployStageType;
        /// <summary>
        /// The OCID of the artifact that contains the deployment specification.
        /// </summary>
        public readonly string DeploymentSpecDeployArtifactId;
        /// <summary>
        /// Optional description about the deployment stage.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Deployment stage display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// A Docker image artifact OCID.
        /// </summary>
        public readonly string DockerImageDeployArtifactId;
        /// <summary>
        /// Specifies a failure policy for a compute instance group rolling deployment stage.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeployStageFailurePolicyResult> FailurePolicies;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// Function environment OCID.
        /// </summary>
        public readonly string FunctionDeployEnvironmentId;
        /// <summary>
        /// Timeout for execution of the Function. Value in seconds.
        /// </summary>
        public readonly int FunctionTimeoutInSeconds;
        /// <summary>
        /// Collection of backend environment IP addresses.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeployStageGreenBackendIpResult> GreenBackendIps;
        /// <summary>
        /// Helm chart artifact OCID.
        /// </summary>
        public readonly string HelmChartDeployArtifactId;
        /// <summary>
        /// Unique identifier that is immutable on creation.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A boolean flag specifies whether this stage executes asynchronously.
        /// </summary>
        public readonly bool IsAsync;
        /// <summary>
        /// A boolean flag specifies whether the invoked function must be validated.
        /// </summary>
        public readonly bool IsValidationEnabled;
        /// <summary>
        /// List of Kubernetes manifest artifact OCIDs.
        /// </summary>
        public readonly ImmutableArray<string> KubernetesManifestDeployArtifactIds;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// Specifies config for load balancer traffic shift stages. The Load Balancer specified here should be an Application Load Balancer type. Network Load Balancers are not supported.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeployStageLoadBalancerConfigResult> LoadBalancerConfigs;
        /// <summary>
        /// Maximum usable memory for the Function (in MB).
        /// </summary>
        public readonly string MaxMemoryInMbs;
        /// <summary>
        /// Default Namespace to be used for Kubernetes deployment when not specified in the manifest.
        /// </summary>
        public readonly string Namespace;
        /// <summary>
        /// The OCID of the upstream OKE blue-green deployment stage in this pipeline.
        /// </summary>
        public readonly string OkeBlueGreenDeployStageId;
        /// <summary>
        /// The OCID of an upstream OKE canary deployment stage in this pipeline.
        /// </summary>
        public readonly string OkeCanaryDeployStageId;
        /// <summary>
        /// The OCID of an upstream OKE canary deployment traffic shift stage in this pipeline.
        /// </summary>
        public readonly string OkeCanaryTrafficShiftDeployStageId;
        /// <summary>
        /// Kubernetes cluster environment OCID for deployment.
        /// </summary>
        public readonly string OkeClusterDeployEnvironmentId;
        /// <summary>
        /// Specifies config for load balancer traffic shift stages. The Load Balancer specified here should be an Application Load Balancer type. Network Load Balancers are not supported.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeployStageProductionLoadBalancerConfigResult> ProductionLoadBalancerConfigs;
        /// <summary>
        /// The OCID of a project.
        /// </summary>
        public readonly string ProjectId;
        /// <summary>
        /// Release name of the Helm chart.
        /// </summary>
        public readonly string ReleaseName;
        /// <summary>
        /// Specifies the rollback policy. This is initiated on the failure of certain stage types.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeployStageRollbackPolicyResult> RollbackPolicies;
        /// <summary>
        /// Description of rollout policy for load balancer traffic shift stage.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeployStageRolloutPolicyResult> RolloutPolicies;
        /// <summary>
        /// The current state of the deployment stage.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> SystemTags;
        /// <summary>
        /// Specifies config for load balancer traffic shift stages. The Load Balancer specified here should be an Application Load Balancer type. Network Load Balancers are not supported.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeployStageTestLoadBalancerConfigResult> TestLoadBalancerConfigs;
        /// <summary>
        /// Time the deployment stage was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// Time the deployment stage was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// Time to wait for execution of a helm stage. Defaults to 300 seconds.
        /// </summary>
        public readonly int TimeoutInSeconds;
        /// <summary>
        /// Specifies the target or destination backend set.
        /// </summary>
        public readonly string TrafficShiftTarget;
        /// <summary>
        /// List of values.yaml file artifact OCIDs.
        /// </summary>
        public readonly ImmutableArray<string> ValuesArtifactIds;
        /// <summary>
        /// Specifies wait criteria for the Wait stage.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeployStageWaitCriteriaResult> WaitCriterias;

        [OutputConstructor]
        private GetDeployStageResult(
            ImmutableArray<Outputs.GetDeployStageApprovalPolicyResult> approvalPolicies,

            ImmutableArray<Outputs.GetDeployStageBlueBackendIpResult> blueBackendIps,

            ImmutableArray<Outputs.GetDeployStageBlueGreenStrategyResult> blueGreenStrategies,

            ImmutableArray<Outputs.GetDeployStageCanaryStrategyResult> canaryStrategies,

            string compartmentId,

            string computeInstanceGroupBlueGreenDeploymentDeployStageId,

            string computeInstanceGroupCanaryDeployStageId,

            string computeInstanceGroupCanaryTrafficShiftDeployStageId,

            string computeInstanceGroupDeployEnvironmentId,

            ImmutableDictionary<string, object> config,

            ImmutableDictionary<string, object> definedTags,

            string deployArtifactId,

            ImmutableArray<string> deployArtifactIds,

            string deployEnvironmentIdA,

            string deployEnvironmentIdB,

            string deployPipelineId,

            string deployStageId,

            ImmutableArray<Outputs.GetDeployStageDeployStagePredecessorCollectionResult> deployStagePredecessorCollections,

            string deployStageType,

            string deploymentSpecDeployArtifactId,

            string description,

            string displayName,

            string dockerImageDeployArtifactId,

            ImmutableArray<Outputs.GetDeployStageFailurePolicyResult> failurePolicies,

            ImmutableDictionary<string, object> freeformTags,

            string functionDeployEnvironmentId,

            int functionTimeoutInSeconds,

            ImmutableArray<Outputs.GetDeployStageGreenBackendIpResult> greenBackendIps,

            string helmChartDeployArtifactId,

            string id,

            bool isAsync,

            bool isValidationEnabled,

            ImmutableArray<string> kubernetesManifestDeployArtifactIds,

            string lifecycleDetails,

            ImmutableArray<Outputs.GetDeployStageLoadBalancerConfigResult> loadBalancerConfigs,

            string maxMemoryInMbs,

            string @namespace,

            string okeBlueGreenDeployStageId,

            string okeCanaryDeployStageId,

            string okeCanaryTrafficShiftDeployStageId,

            string okeClusterDeployEnvironmentId,

            ImmutableArray<Outputs.GetDeployStageProductionLoadBalancerConfigResult> productionLoadBalancerConfigs,

            string projectId,

            string releaseName,

            ImmutableArray<Outputs.GetDeployStageRollbackPolicyResult> rollbackPolicies,

            ImmutableArray<Outputs.GetDeployStageRolloutPolicyResult> rolloutPolicies,

            string state,

            ImmutableDictionary<string, object> systemTags,

            ImmutableArray<Outputs.GetDeployStageTestLoadBalancerConfigResult> testLoadBalancerConfigs,

            string timeCreated,

            string timeUpdated,

            int timeoutInSeconds,

            string trafficShiftTarget,

            ImmutableArray<string> valuesArtifactIds,

            ImmutableArray<Outputs.GetDeployStageWaitCriteriaResult> waitCriterias)
        {
            ApprovalPolicies = approvalPolicies;
            BlueBackendIps = blueBackendIps;
            BlueGreenStrategies = blueGreenStrategies;
            CanaryStrategies = canaryStrategies;
            CompartmentId = compartmentId;
            ComputeInstanceGroupBlueGreenDeploymentDeployStageId = computeInstanceGroupBlueGreenDeploymentDeployStageId;
            ComputeInstanceGroupCanaryDeployStageId = computeInstanceGroupCanaryDeployStageId;
            ComputeInstanceGroupCanaryTrafficShiftDeployStageId = computeInstanceGroupCanaryTrafficShiftDeployStageId;
            ComputeInstanceGroupDeployEnvironmentId = computeInstanceGroupDeployEnvironmentId;
            Config = config;
            DefinedTags = definedTags;
            DeployArtifactId = deployArtifactId;
            DeployArtifactIds = deployArtifactIds;
            DeployEnvironmentIdA = deployEnvironmentIdA;
            DeployEnvironmentIdB = deployEnvironmentIdB;
            DeployPipelineId = deployPipelineId;
            DeployStageId = deployStageId;
            DeployStagePredecessorCollections = deployStagePredecessorCollections;
            DeployStageType = deployStageType;
            DeploymentSpecDeployArtifactId = deploymentSpecDeployArtifactId;
            Description = description;
            DisplayName = displayName;
            DockerImageDeployArtifactId = dockerImageDeployArtifactId;
            FailurePolicies = failurePolicies;
            FreeformTags = freeformTags;
            FunctionDeployEnvironmentId = functionDeployEnvironmentId;
            FunctionTimeoutInSeconds = functionTimeoutInSeconds;
            GreenBackendIps = greenBackendIps;
            HelmChartDeployArtifactId = helmChartDeployArtifactId;
            Id = id;
            IsAsync = isAsync;
            IsValidationEnabled = isValidationEnabled;
            KubernetesManifestDeployArtifactIds = kubernetesManifestDeployArtifactIds;
            LifecycleDetails = lifecycleDetails;
            LoadBalancerConfigs = loadBalancerConfigs;
            MaxMemoryInMbs = maxMemoryInMbs;
            Namespace = @namespace;
            OkeBlueGreenDeployStageId = okeBlueGreenDeployStageId;
            OkeCanaryDeployStageId = okeCanaryDeployStageId;
            OkeCanaryTrafficShiftDeployStageId = okeCanaryTrafficShiftDeployStageId;
            OkeClusterDeployEnvironmentId = okeClusterDeployEnvironmentId;
            ProductionLoadBalancerConfigs = productionLoadBalancerConfigs;
            ProjectId = projectId;
            ReleaseName = releaseName;
            RollbackPolicies = rollbackPolicies;
            RolloutPolicies = rolloutPolicies;
            State = state;
            SystemTags = systemTags;
            TestLoadBalancerConfigs = testLoadBalancerConfigs;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            TimeoutInSeconds = timeoutInSeconds;
            TrafficShiftTarget = trafficShiftTarget;
            ValuesArtifactIds = valuesArtifactIds;
            WaitCriterias = waitCriterias;
        }
    }
}