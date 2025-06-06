// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Model Deployment resource in Oracle Cloud Infrastructure Datascience service.
 *
 * Creates a new model deployment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testModelDeployment = new oci.datascience.ModelDeployment("test_model_deployment", {
 *     compartmentId: compartmentId,
 *     modelDeploymentConfigurationDetails: {
 *         deploymentType: modelDeploymentModelDeploymentConfigurationDetailsDeploymentType,
 *         modelConfigurationDetails: {
 *             instanceConfiguration: {
 *                 instanceShapeName: testShape.name,
 *                 modelDeploymentInstanceShapeConfigDetails: {
 *                     cpuBaseline: modelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsInstanceConfigurationModelDeploymentInstanceShapeConfigDetailsCpuBaseline,
 *                     memoryInGbs: modelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsInstanceConfigurationModelDeploymentInstanceShapeConfigDetailsMemoryInGbs,
 *                     ocpus: modelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsInstanceConfigurationModelDeploymentInstanceShapeConfigDetailsOcpus,
 *                 },
 *                 privateEndpointId: testPrivateEndpoint.id,
 *                 subnetId: testSubnet.id,
 *             },
 *             modelId: testModel.id,
 *             bandwidthMbps: modelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsBandwidthMbps,
 *             maximumBandwidthMbps: modelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsMaximumBandwidthMbps,
 *             scalingPolicy: {
 *                 policyType: modelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyPolicyType,
 *                 autoScalingPolicies: [{
 *                     autoScalingPolicyType: modelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyAutoScalingPoliciesAutoScalingPolicyType,
 *                     initialInstanceCount: modelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyAutoScalingPoliciesInitialInstanceCount,
 *                     maximumInstanceCount: modelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyAutoScalingPoliciesMaximumInstanceCount,
 *                     minimumInstanceCount: modelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyAutoScalingPoliciesMinimumInstanceCount,
 *                     rules: [{
 *                         metricExpressionRuleType: modelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyAutoScalingPoliciesRulesMetricExpressionRuleType,
 *                         scaleInConfiguration: {
 *                             instanceCountAdjustment: modelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyAutoScalingPoliciesRulesScaleInConfigurationInstanceCountAdjustment,
 *                             pendingDuration: modelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyAutoScalingPoliciesRulesScaleInConfigurationPendingDuration,
 *                             query: modelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyAutoScalingPoliciesRulesScaleInConfigurationQuery,
 *                             scalingConfigurationType: modelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyAutoScalingPoliciesRulesScaleInConfigurationScalingConfigurationType,
 *                             threshold: modelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyAutoScalingPoliciesRulesScaleInConfigurationThreshold,
 *                         },
 *                         scaleOutConfiguration: {
 *                             instanceCountAdjustment: modelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyAutoScalingPoliciesRulesScaleOutConfigurationInstanceCountAdjustment,
 *                             pendingDuration: modelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyAutoScalingPoliciesRulesScaleOutConfigurationPendingDuration,
 *                             query: modelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyAutoScalingPoliciesRulesScaleOutConfigurationQuery,
 *                             scalingConfigurationType: modelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyAutoScalingPoliciesRulesScaleOutConfigurationScalingConfigurationType,
 *                             threshold: modelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyAutoScalingPoliciesRulesScaleOutConfigurationThreshold,
 *                         },
 *                         metricType: modelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyAutoScalingPoliciesRulesMetricType,
 *                     }],
 *                 }],
 *                 coolDownInSeconds: modelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyCoolDownInSeconds,
 *                 instanceCount: modelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyInstanceCount,
 *                 isEnabled: modelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyIsEnabled,
 *             },
 *         },
 *         environmentConfigurationDetails: {
 *             environmentConfigurationType: modelDeploymentModelDeploymentConfigurationDetailsEnvironmentConfigurationDetailsEnvironmentConfigurationType,
 *             cmds: modelDeploymentModelDeploymentConfigurationDetailsEnvironmentConfigurationDetailsCmd,
 *             entrypoints: modelDeploymentModelDeploymentConfigurationDetailsEnvironmentConfigurationDetailsEntrypoint,
 *             environmentVariables: modelDeploymentModelDeploymentConfigurationDetailsEnvironmentConfigurationDetailsEnvironmentVariables,
 *             healthCheckPort: modelDeploymentModelDeploymentConfigurationDetailsEnvironmentConfigurationDetailsHealthCheckPort,
 *             image: modelDeploymentModelDeploymentConfigurationDetailsEnvironmentConfigurationDetailsImage,
 *             imageDigest: modelDeploymentModelDeploymentConfigurationDetailsEnvironmentConfigurationDetailsImageDigest,
 *             serverPort: modelDeploymentModelDeploymentConfigurationDetailsEnvironmentConfigurationDetailsServerPort,
 *         },
 *     },
 *     projectId: testProject.id,
 *     categoryLogDetails: {
 *         access: {
 *             logGroupId: testLogGroup.id,
 *             logId: testLog.id,
 *         },
 *         predict: {
 *             logGroupId: testLogGroup.id,
 *             logId: testLog.id,
 *         },
 *     },
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     description: modelDeploymentDescription,
 *     displayName: modelDeploymentDisplayName,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     opcParentRptUrl: modelDeploymentOpcParentRptUrl,
 * });
 * ```
 *
 * ## Import
 *
 * ModelDeployments can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:DataScience/modelDeployment:ModelDeployment test_model_deployment "id"
 * ```
 */
export class ModelDeployment extends pulumi.CustomResource {
    /**
     * Get an existing ModelDeployment resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ModelDeploymentState, opts?: pulumi.CustomResourceOptions): ModelDeployment {
        return new ModelDeployment(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:DataScience/modelDeployment:ModelDeployment';

    /**
     * Returns true if the given object is an instance of ModelDeployment.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is ModelDeployment {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === ModelDeployment.__pulumiType;
    }

    /**
     * (Updatable) The log details for each category.
     */
    public readonly categoryLogDetails!: pulumi.Output<outputs.DataScience.ModelDeploymentCategoryLogDetails>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the model deployment.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the model deployment.
     */
    public /*out*/ readonly createdBy!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) A short description of the model deployment.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * (Updatable) A user-friendly display name for the resource. Does not have to be unique, and can be modified. Avoid entering confidential information. Example: `My ModelDeployment`
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * Details about the state of the model deployment.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * (Updatable) The model deployment configuration details.
     */
    public readonly modelDeploymentConfigurationDetails!: pulumi.Output<outputs.DataScience.ModelDeploymentModelDeploymentConfigurationDetails>;
    /**
     * Model deployment system data.
     */
    public /*out*/ readonly modelDeploymentSystemDatas!: pulumi.Output<outputs.DataScience.ModelDeploymentModelDeploymentSystemData[]>;
    /**
     * The URL to interact with the model deployment.
     */
    public /*out*/ readonly modelDeploymentUrl!: pulumi.Output<string>;
    /**
     * URL to fetch the Resource Principal Token from the parent resource.
     */
    public readonly opcParentRptUrl!: pulumi.Output<string | undefined>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model deployment.
     */
    public readonly projectId!: pulumi.Output<string>;
    /**
     * (Updatable) The target state for the Model Deployment. Could be set to `ACTIVE` or `INACTIVE`. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly state!: pulumi.Output<string>;
    /**
     * The date and time the resource was created, in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2019-08-25T21:10:29.41Z
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;

    /**
     * Create a ModelDeployment resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ModelDeploymentArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ModelDeploymentArgs | ModelDeploymentState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ModelDeploymentState | undefined;
            resourceInputs["categoryLogDetails"] = state ? state.categoryLogDetails : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["createdBy"] = state ? state.createdBy : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["modelDeploymentConfigurationDetails"] = state ? state.modelDeploymentConfigurationDetails : undefined;
            resourceInputs["modelDeploymentSystemDatas"] = state ? state.modelDeploymentSystemDatas : undefined;
            resourceInputs["modelDeploymentUrl"] = state ? state.modelDeploymentUrl : undefined;
            resourceInputs["opcParentRptUrl"] = state ? state.opcParentRptUrl : undefined;
            resourceInputs["projectId"] = state ? state.projectId : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
        } else {
            const args = argsOrState as ModelDeploymentArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.modelDeploymentConfigurationDetails === undefined) && !opts.urn) {
                throw new Error("Missing required property 'modelDeploymentConfigurationDetails'");
            }
            if ((!args || args.projectId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'projectId'");
            }
            resourceInputs["categoryLogDetails"] = args ? args.categoryLogDetails : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["description"] = args ? args.description : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["modelDeploymentConfigurationDetails"] = args ? args.modelDeploymentConfigurationDetails : undefined;
            resourceInputs["opcParentRptUrl"] = args ? args.opcParentRptUrl : undefined;
            resourceInputs["projectId"] = args ? args.projectId : undefined;
            resourceInputs["state"] = args ? args.state : undefined;
            resourceInputs["createdBy"] = undefined /*out*/;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["modelDeploymentSystemDatas"] = undefined /*out*/;
            resourceInputs["modelDeploymentUrl"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(ModelDeployment.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering ModelDeployment resources.
 */
export interface ModelDeploymentState {
    /**
     * (Updatable) The log details for each category.
     */
    categoryLogDetails?: pulumi.Input<inputs.DataScience.ModelDeploymentCategoryLogDetails>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the model deployment.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the model deployment.
     */
    createdBy?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) A short description of the model deployment.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) A user-friendly display name for the resource. Does not have to be unique, and can be modified. Avoid entering confidential information. Example: `My ModelDeployment`
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * Details about the state of the model deployment.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * (Updatable) The model deployment configuration details.
     */
    modelDeploymentConfigurationDetails?: pulumi.Input<inputs.DataScience.ModelDeploymentModelDeploymentConfigurationDetails>;
    /**
     * Model deployment system data.
     */
    modelDeploymentSystemDatas?: pulumi.Input<pulumi.Input<inputs.DataScience.ModelDeploymentModelDeploymentSystemData>[]>;
    /**
     * The URL to interact with the model deployment.
     */
    modelDeploymentUrl?: pulumi.Input<string>;
    /**
     * URL to fetch the Resource Principal Token from the parent resource.
     */
    opcParentRptUrl?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model deployment.
     */
    projectId?: pulumi.Input<string>;
    /**
     * (Updatable) The target state for the Model Deployment. Could be set to `ACTIVE` or `INACTIVE`. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    state?: pulumi.Input<string>;
    /**
     * The date and time the resource was created, in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2019-08-25T21:10:29.41Z
     */
    timeCreated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a ModelDeployment resource.
 */
export interface ModelDeploymentArgs {
    /**
     * (Updatable) The log details for each category.
     */
    categoryLogDetails?: pulumi.Input<inputs.DataScience.ModelDeploymentCategoryLogDetails>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the model deployment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) A short description of the model deployment.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) A user-friendly display name for the resource. Does not have to be unique, and can be modified. Avoid entering confidential information. Example: `My ModelDeployment`
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) The model deployment configuration details.
     */
    modelDeploymentConfigurationDetails: pulumi.Input<inputs.DataScience.ModelDeploymentModelDeploymentConfigurationDetails>;
    /**
     * URL to fetch the Resource Principal Token from the parent resource.
     */
    opcParentRptUrl?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model deployment.
     */
    projectId: pulumi.Input<string>;
    /**
     * (Updatable) The target state for the Model Deployment. Could be set to `ACTIVE` or `INACTIVE`. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    state?: pulumi.Input<string>;
}
