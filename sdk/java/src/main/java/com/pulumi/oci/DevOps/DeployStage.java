// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.DevOps.DeployStageArgs;
import com.pulumi.oci.DevOps.inputs.DeployStageState;
import com.pulumi.oci.DevOps.outputs.DeployStageApprovalPolicy;
import com.pulumi.oci.DevOps.outputs.DeployStageBlueBackendIps;
import com.pulumi.oci.DevOps.outputs.DeployStageBlueGreenStrategy;
import com.pulumi.oci.DevOps.outputs.DeployStageCanaryStrategy;
import com.pulumi.oci.DevOps.outputs.DeployStageDeployStagePredecessorCollection;
import com.pulumi.oci.DevOps.outputs.DeployStageFailurePolicy;
import com.pulumi.oci.DevOps.outputs.DeployStageGreenBackendIps;
import com.pulumi.oci.DevOps.outputs.DeployStageLoadBalancerConfig;
import com.pulumi.oci.DevOps.outputs.DeployStageProductionLoadBalancerConfig;
import com.pulumi.oci.DevOps.outputs.DeployStageRollbackPolicy;
import com.pulumi.oci.DevOps.outputs.DeployStageRolloutPolicy;
import com.pulumi.oci.DevOps.outputs.DeployStageTestLoadBalancerConfig;
import com.pulumi.oci.DevOps.outputs.DeployStageWaitCriteria;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * This resource provides the Deploy Stage resource in Oracle Cloud Infrastructure Devops service.
 * 
 * Creates a new deployment stage.
 * 
 * ## Import
 * 
 * DeployStages can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:DevOps/deployStage:DeployStage test_deploy_stage &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:DevOps/deployStage:DeployStage")
public class DeployStage extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) Specifies the approval policy.
     * 
     */
    @Export(name="approvalPolicy", type=DeployStageApprovalPolicy.class, parameters={})
    private Output<DeployStageApprovalPolicy> approvalPolicy;

    /**
     * @return (Updatable) Specifies the approval policy.
     * 
     */
    public Output<DeployStageApprovalPolicy> approvalPolicy() {
        return this.approvalPolicy;
    }
    /**
     * (Updatable) Collection of backend environment IP addresses.
     * 
     */
    @Export(name="blueBackendIps", type=DeployStageBlueBackendIps.class, parameters={})
    private Output<DeployStageBlueBackendIps> blueBackendIps;

    /**
     * @return (Updatable) Collection of backend environment IP addresses.
     * 
     */
    public Output<DeployStageBlueBackendIps> blueBackendIps() {
        return this.blueBackendIps;
    }
    /**
     * Specifies the required blue green release strategy for OKE deployment.
     * 
     */
    @Export(name="blueGreenStrategy", type=DeployStageBlueGreenStrategy.class, parameters={})
    private Output<DeployStageBlueGreenStrategy> blueGreenStrategy;

    /**
     * @return Specifies the required blue green release strategy for OKE deployment.
     * 
     */
    public Output<DeployStageBlueGreenStrategy> blueGreenStrategy() {
        return this.blueGreenStrategy;
    }
    /**
     * Specifies the required canary release strategy for OKE deployment.
     * 
     */
    @Export(name="canaryStrategy", type=DeployStageCanaryStrategy.class, parameters={})
    private Output<DeployStageCanaryStrategy> canaryStrategy;

    /**
     * @return Specifies the required canary release strategy for OKE deployment.
     * 
     */
    public Output<DeployStageCanaryStrategy> canaryStrategy() {
        return this.canaryStrategy;
    }
    /**
     * The OCID of a compartment.
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return The OCID of a compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * The OCID of the upstream compute instance group blue-green deployment stage in this pipeline.
     * 
     */
    @Export(name="computeInstanceGroupBlueGreenDeploymentDeployStageId", type=String.class, parameters={})
    private Output<String> computeInstanceGroupBlueGreenDeploymentDeployStageId;

    /**
     * @return The OCID of the upstream compute instance group blue-green deployment stage in this pipeline.
     * 
     */
    public Output<String> computeInstanceGroupBlueGreenDeploymentDeployStageId() {
        return this.computeInstanceGroupBlueGreenDeploymentDeployStageId;
    }
    /**
     * A compute instance group canary stage OCID for load balancer.
     * 
     */
    @Export(name="computeInstanceGroupCanaryDeployStageId", type=String.class, parameters={})
    private Output<String> computeInstanceGroupCanaryDeployStageId;

    /**
     * @return A compute instance group canary stage OCID for load balancer.
     * 
     */
    public Output<String> computeInstanceGroupCanaryDeployStageId() {
        return this.computeInstanceGroupCanaryDeployStageId;
    }
    /**
     * (Updatable) A compute instance group canary traffic shift stage OCID for load balancer.
     * 
     */
    @Export(name="computeInstanceGroupCanaryTrafficShiftDeployStageId", type=String.class, parameters={})
    private Output<String> computeInstanceGroupCanaryTrafficShiftDeployStageId;

    /**
     * @return (Updatable) A compute instance group canary traffic shift stage OCID for load balancer.
     * 
     */
    public Output<String> computeInstanceGroupCanaryTrafficShiftDeployStageId() {
        return this.computeInstanceGroupCanaryTrafficShiftDeployStageId;
    }
    /**
     * (Updatable) A compute instance group environment OCID for rolling deployment.
     * 
     */
    @Export(name="computeInstanceGroupDeployEnvironmentId", type=String.class, parameters={})
    private Output<String> computeInstanceGroupDeployEnvironmentId;

    /**
     * @return (Updatable) A compute instance group environment OCID for rolling deployment.
     * 
     */
    public Output<String> computeInstanceGroupDeployEnvironmentId() {
        return this.computeInstanceGroupDeployEnvironmentId;
    }
    /**
     * (Updatable) User provided key and value pair configuration, which is assigned through constants or parameter.
     * 
     */
    @Export(name="config", type=Map.class, parameters={String.class, Object.class})
    private Output</* @Nullable */ Map<String,Object>> config;

    /**
     * @return (Updatable) User provided key and value pair configuration, which is assigned through constants or parameter.
     * 
     */
    public Output<Optional<Map<String,Object>>> config() {
        return Codegen.optional(this.config);
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="definedTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,Object>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) Optional artifact OCID. The artifact will be included in the body for the function invocation during the stage&#39;s execution. If the DeployArtifact.argumentSubstituitionMode is set to SUBSTITUTE_PLACEHOLDERS, then the pipeline parameter values will be used to replace the placeholders in the artifact content.
     * 
     */
    @Export(name="deployArtifactId", type=String.class, parameters={})
    private Output</* @Nullable */ String> deployArtifactId;

    /**
     * @return (Updatable) Optional artifact OCID. The artifact will be included in the body for the function invocation during the stage&#39;s execution. If the DeployArtifact.argumentSubstituitionMode is set to SUBSTITUTE_PLACEHOLDERS, then the pipeline parameter values will be used to replace the placeholders in the artifact content.
     * 
     */
    public Output<Optional<String>> deployArtifactId() {
        return Codegen.optional(this.deployArtifactId);
    }
    /**
     * (Updatable) The list of file artifact OCIDs to deploy.
     * 
     */
    @Export(name="deployArtifactIds", type=List.class, parameters={String.class})
    private Output</* @Nullable */ List<String>> deployArtifactIds;

    /**
     * @return (Updatable) The list of file artifact OCIDs to deploy.
     * 
     */
    public Output<Optional<List<String>>> deployArtifactIds() {
        return Codegen.optional(this.deployArtifactIds);
    }
    /**
     * First compute instance group environment OCID for deployment.
     * 
     */
    @Export(name="deployEnvironmentIdA", type=String.class, parameters={})
    private Output<String> deployEnvironmentIdA;

    /**
     * @return First compute instance group environment OCID for deployment.
     * 
     */
    public Output<String> deployEnvironmentIdA() {
        return this.deployEnvironmentIdA;
    }
    /**
     * Second compute instance group environment OCID for deployment.
     * 
     */
    @Export(name="deployEnvironmentIdB", type=String.class, parameters={})
    private Output<String> deployEnvironmentIdB;

    /**
     * @return Second compute instance group environment OCID for deployment.
     * 
     */
    public Output<String> deployEnvironmentIdB() {
        return this.deployEnvironmentIdB;
    }
    /**
     * The OCID of a pipeline.
     * 
     */
    @Export(name="deployPipelineId", type=String.class, parameters={})
    private Output<String> deployPipelineId;

    /**
     * @return The OCID of a pipeline.
     * 
     */
    public Output<String> deployPipelineId() {
        return this.deployPipelineId;
    }
    /**
     * (Updatable) Collection containing the predecessors of a stage.
     * 
     */
    @Export(name="deployStagePredecessorCollection", type=DeployStageDeployStagePredecessorCollection.class, parameters={})
    private Output<DeployStageDeployStagePredecessorCollection> deployStagePredecessorCollection;

    /**
     * @return (Updatable) Collection containing the predecessors of a stage.
     * 
     */
    public Output<DeployStageDeployStagePredecessorCollection> deployStagePredecessorCollection() {
        return this.deployStagePredecessorCollection;
    }
    /**
     * (Updatable) Deployment stage type.
     * 
     */
    @Export(name="deployStageType", type=String.class, parameters={})
    private Output<String> deployStageType;

    /**
     * @return (Updatable) Deployment stage type.
     * 
     */
    public Output<String> deployStageType() {
        return this.deployStageType;
    }
    /**
     * (Updatable) The OCID of the artifact that contains the deployment specification.
     * 
     */
    @Export(name="deploymentSpecDeployArtifactId", type=String.class, parameters={})
    private Output<String> deploymentSpecDeployArtifactId;

    /**
     * @return (Updatable) The OCID of the artifact that contains the deployment specification.
     * 
     */
    public Output<String> deploymentSpecDeployArtifactId() {
        return this.deploymentSpecDeployArtifactId;
    }
    /**
     * (Updatable) Optional description about the deployment stage.
     * 
     */
    @Export(name="description", type=String.class, parameters={})
    private Output<String> description;

    /**
     * @return (Updatable) Optional description about the deployment stage.
     * 
     */
    public Output<String> description() {
        return this.description;
    }
    /**
     * (Updatable) Deployment stage display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return (Updatable) Deployment stage display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * (Updatable) A Docker image artifact OCID.
     * 
     */
    @Export(name="dockerImageDeployArtifactId", type=String.class, parameters={})
    private Output<String> dockerImageDeployArtifactId;

    /**
     * @return (Updatable) A Docker image artifact OCID.
     * 
     */
    public Output<String> dockerImageDeployArtifactId() {
        return this.dockerImageDeployArtifactId;
    }
    /**
     * (Updatable) Specifies a failure policy for a compute instance group rolling deployment stage.
     * 
     */
    @Export(name="failurePolicy", type=DeployStageFailurePolicy.class, parameters={})
    private Output<DeployStageFailurePolicy> failurePolicy;

    /**
     * @return (Updatable) Specifies a failure policy for a compute instance group rolling deployment stage.
     * 
     */
    public Output<DeployStageFailurePolicy> failurePolicy() {
        return this.failurePolicy;
    }
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="freeformTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,Object>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * (Updatable) Function environment OCID.
     * 
     */
    @Export(name="functionDeployEnvironmentId", type=String.class, parameters={})
    private Output<String> functionDeployEnvironmentId;

    /**
     * @return (Updatable) Function environment OCID.
     * 
     */
    public Output<String> functionDeployEnvironmentId() {
        return this.functionDeployEnvironmentId;
    }
    /**
     * (Updatable) Timeout for execution of the Function. Value in seconds.
     * 
     */
    @Export(name="functionTimeoutInSeconds", type=Integer.class, parameters={})
    private Output<Integer> functionTimeoutInSeconds;

    /**
     * @return (Updatable) Timeout for execution of the Function. Value in seconds.
     * 
     */
    public Output<Integer> functionTimeoutInSeconds() {
        return this.functionTimeoutInSeconds;
    }
    /**
     * (Updatable) Collection of backend environment IP addresses.
     * 
     */
    @Export(name="greenBackendIps", type=DeployStageGreenBackendIps.class, parameters={})
    private Output<DeployStageGreenBackendIps> greenBackendIps;

    /**
     * @return (Updatable) Collection of backend environment IP addresses.
     * 
     */
    public Output<DeployStageGreenBackendIps> greenBackendIps() {
        return this.greenBackendIps;
    }
    /**
     * (Updatable) Helm chart artifact OCID.
     * 
     */
    @Export(name="helmChartDeployArtifactId", type=String.class, parameters={})
    private Output<String> helmChartDeployArtifactId;

    /**
     * @return (Updatable) Helm chart artifact OCID.
     * 
     */
    public Output<String> helmChartDeployArtifactId() {
        return this.helmChartDeployArtifactId;
    }
    /**
     * (Updatable) A boolean flag specifies whether this stage executes asynchronously.
     * 
     */
    @Export(name="isAsync", type=Boolean.class, parameters={})
    private Output<Boolean> isAsync;

    /**
     * @return (Updatable) A boolean flag specifies whether this stage executes asynchronously.
     * 
     */
    public Output<Boolean> isAsync() {
        return this.isAsync;
    }
    /**
     * (Updatable) A boolean flag specifies whether the invoked function should be validated.
     * 
     */
    @Export(name="isValidationEnabled", type=Boolean.class, parameters={})
    private Output<Boolean> isValidationEnabled;

    /**
     * @return (Updatable) A boolean flag specifies whether the invoked function should be validated.
     * 
     */
    public Output<Boolean> isValidationEnabled() {
        return this.isValidationEnabled;
    }
    /**
     * (Updatable) List of Kubernetes manifest artifact OCIDs.
     * 
     */
    @Export(name="kubernetesManifestDeployArtifactIds", type=List.class, parameters={String.class})
    private Output</* @Nullable */ List<String>> kubernetesManifestDeployArtifactIds;

    /**
     * @return (Updatable) List of Kubernetes manifest artifact OCIDs.
     * 
     */
    public Output<Optional<List<String>>> kubernetesManifestDeployArtifactIds() {
        return Codegen.optional(this.kubernetesManifestDeployArtifactIds);
    }
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    @Export(name="lifecycleDetails", type=String.class, parameters={})
    private Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * (Updatable) Specifies config for load balancer traffic shift stages. The Load Balancer specified here should be an Application Load Balancer type. Network Load Balancers are not supported.
     * 
     */
    @Export(name="loadBalancerConfig", type=DeployStageLoadBalancerConfig.class, parameters={})
    private Output<DeployStageLoadBalancerConfig> loadBalancerConfig;

    /**
     * @return (Updatable) Specifies config for load balancer traffic shift stages. The Load Balancer specified here should be an Application Load Balancer type. Network Load Balancers are not supported.
     * 
     */
    public Output<DeployStageLoadBalancerConfig> loadBalancerConfig() {
        return this.loadBalancerConfig;
    }
    /**
     * (Updatable) Maximum usable memory for the Function (in MB).
     * 
     */
    @Export(name="maxMemoryInMbs", type=String.class, parameters={})
    private Output<String> maxMemoryInMbs;

    /**
     * @return (Updatable) Maximum usable memory for the Function (in MB).
     * 
     */
    public Output<String> maxMemoryInMbs() {
        return this.maxMemoryInMbs;
    }
    /**
     * (Updatable) Default namespace to be used for Kubernetes deployment when not specified in the manifest.
     * 
     */
    @Export(name="namespace", type=String.class, parameters={})
    private Output<String> namespace;

    /**
     * @return (Updatable) Default namespace to be used for Kubernetes deployment when not specified in the manifest.
     * 
     */
    public Output<String> namespace() {
        return this.namespace;
    }
    /**
     * The OCID of the upstream OKE blue-green deployment stage in this pipeline.
     * 
     */
    @Export(name="okeBlueGreenDeployStageId", type=String.class, parameters={})
    private Output<String> okeBlueGreenDeployStageId;

    /**
     * @return The OCID of the upstream OKE blue-green deployment stage in this pipeline.
     * 
     */
    public Output<String> okeBlueGreenDeployStageId() {
        return this.okeBlueGreenDeployStageId;
    }
    /**
     * The OCID of an upstream OKE canary deployment stage in this pipeline.
     * 
     */
    @Export(name="okeCanaryDeployStageId", type=String.class, parameters={})
    private Output<String> okeCanaryDeployStageId;

    /**
     * @return The OCID of an upstream OKE canary deployment stage in this pipeline.
     * 
     */
    public Output<String> okeCanaryDeployStageId() {
        return this.okeCanaryDeployStageId;
    }
    /**
     * The OCID of an upstream OKE canary deployment traffic shift stage in this pipeline.
     * 
     */
    @Export(name="okeCanaryTrafficShiftDeployStageId", type=String.class, parameters={})
    private Output<String> okeCanaryTrafficShiftDeployStageId;

    /**
     * @return The OCID of an upstream OKE canary deployment traffic shift stage in this pipeline.
     * 
     */
    public Output<String> okeCanaryTrafficShiftDeployStageId() {
        return this.okeCanaryTrafficShiftDeployStageId;
    }
    /**
     * (Updatable) Kubernetes cluster environment OCID for deployment.
     * 
     */
    @Export(name="okeClusterDeployEnvironmentId", type=String.class, parameters={})
    private Output<String> okeClusterDeployEnvironmentId;

    /**
     * @return (Updatable) Kubernetes cluster environment OCID for deployment.
     * 
     */
    public Output<String> okeClusterDeployEnvironmentId() {
        return this.okeClusterDeployEnvironmentId;
    }
    /**
     * Specifies configuration for load balancer traffic shift stages. The load balancer specified here should be an Application load balancer type. Network load balancers are not supported.
     * 
     */
    @Export(name="productionLoadBalancerConfig", type=DeployStageProductionLoadBalancerConfig.class, parameters={})
    private Output<DeployStageProductionLoadBalancerConfig> productionLoadBalancerConfig;

    /**
     * @return Specifies configuration for load balancer traffic shift stages. The load balancer specified here should be an Application load balancer type. Network load balancers are not supported.
     * 
     */
    public Output<DeployStageProductionLoadBalancerConfig> productionLoadBalancerConfig() {
        return this.productionLoadBalancerConfig;
    }
    /**
     * The OCID of a project.
     * 
     */
    @Export(name="projectId", type=String.class, parameters={})
    private Output<String> projectId;

    /**
     * @return The OCID of a project.
     * 
     */
    public Output<String> projectId() {
        return this.projectId;
    }
    /**
     * (Updatable) Default name of the chart instance. Must be unique within a Kubernetes namespace.
     * 
     */
    @Export(name="releaseName", type=String.class, parameters={})
    private Output<String> releaseName;

    /**
     * @return (Updatable) Default name of the chart instance. Must be unique within a Kubernetes namespace.
     * 
     */
    public Output<String> releaseName() {
        return this.releaseName;
    }
    /**
     * (Updatable) Specifies the rollback policy. This is initiated on the failure of certain stage types.
     * 
     */
    @Export(name="rollbackPolicy", type=DeployStageRollbackPolicy.class, parameters={})
    private Output<DeployStageRollbackPolicy> rollbackPolicy;

    /**
     * @return (Updatable) Specifies the rollback policy. This is initiated on the failure of certain stage types.
     * 
     */
    public Output<DeployStageRollbackPolicy> rollbackPolicy() {
        return this.rollbackPolicy;
    }
    /**
     * (Updatable) Description of rollout policy for load balancer traffic shift stage.
     * 
     */
    @Export(name="rolloutPolicy", type=DeployStageRolloutPolicy.class, parameters={})
    private Output<DeployStageRolloutPolicy> rolloutPolicy;

    /**
     * @return (Updatable) Description of rollout policy for load balancer traffic shift stage.
     * 
     */
    public Output<DeployStageRolloutPolicy> rolloutPolicy() {
        return this.rolloutPolicy;
    }
    /**
     * The current state of the deployment stage.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current state of the deployment stage.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Export(name="systemTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> systemTags;

    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Output<Map<String,Object>> systemTags() {
        return this.systemTags;
    }
    /**
     * (Updatable) Specifies config for load balancer traffic shift stages. The Load Balancer specified here should be an Application Load Balancer type. Network Load Balancers are not supported.
     * 
     */
    @Export(name="testLoadBalancerConfig", type=DeployStageTestLoadBalancerConfig.class, parameters={})
    private Output<DeployStageTestLoadBalancerConfig> testLoadBalancerConfig;

    /**
     * @return (Updatable) Specifies config for load balancer traffic shift stages. The Load Balancer specified here should be an Application Load Balancer type. Network Load Balancers are not supported.
     * 
     */
    public Output<DeployStageTestLoadBalancerConfig> testLoadBalancerConfig() {
        return this.testLoadBalancerConfig;
    }
    /**
     * Time the deployment stage was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return Time the deployment stage was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * Time the deployment stage was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     * 
     */
    @Export(name="timeUpdated", type=String.class, parameters={})
    private Output<String> timeUpdated;

    /**
     * @return Time the deployment stage was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * (Updatable) Time to wait for execution of a helm stage. Defaults to 300 seconds.
     * 
     */
    @Export(name="timeoutInSeconds", type=Integer.class, parameters={})
    private Output<Integer> timeoutInSeconds;

    /**
     * @return (Updatable) Time to wait for execution of a helm stage. Defaults to 300 seconds.
     * 
     */
    public Output<Integer> timeoutInSeconds() {
        return this.timeoutInSeconds;
    }
    /**
     * (Updatable) Specifies the target or destination backend set.
     * 
     */
    @Export(name="trafficShiftTarget", type=String.class, parameters={})
    private Output<String> trafficShiftTarget;

    /**
     * @return (Updatable) Specifies the target or destination backend set.
     * 
     */
    public Output<String> trafficShiftTarget() {
        return this.trafficShiftTarget;
    }
    /**
     * (Updatable) List of values.yaml file artifact OCIDs.
     * 
     */
    @Export(name="valuesArtifactIds", type=List.class, parameters={String.class})
    private Output<List<String>> valuesArtifactIds;

    /**
     * @return (Updatable) List of values.yaml file artifact OCIDs.
     * 
     */
    public Output<List<String>> valuesArtifactIds() {
        return this.valuesArtifactIds;
    }
    /**
     * (Updatable) Specifies wait criteria for the Wait stage.
     * 
     */
    @Export(name="waitCriteria", type=DeployStageWaitCriteria.class, parameters={})
    private Output<DeployStageWaitCriteria> waitCriteria;

    /**
     * @return (Updatable) Specifies wait criteria for the Wait stage.
     * 
     */
    public Output<DeployStageWaitCriteria> waitCriteria() {
        return this.waitCriteria;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public DeployStage(String name) {
        this(name, DeployStageArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public DeployStage(String name, DeployStageArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public DeployStage(String name, DeployStageArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DevOps/deployStage:DeployStage", name, args == null ? DeployStageArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private DeployStage(String name, Output<String> id, @Nullable DeployStageState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DevOps/deployStage:DeployStage", name, state, makeResourceOptions(options, id));
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<String> id) {
        var defaultOptions = com.pulumi.resources.CustomResourceOptions.builder()
            .version(Utilities.getVersion())
            .build();
        return com.pulumi.resources.CustomResourceOptions.merge(defaultOptions, options, id);
    }

    /**
     * Get an existing Host resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state
     * @param options Optional settings to control the behavior of the CustomResource.
     */
    public static DeployStage get(String name, Output<String> id, @Nullable DeployStageState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new DeployStage(name, id, state, options);
    }
}