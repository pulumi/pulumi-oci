// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Deploy Pipeline resource in Oracle Cloud Infrastructure Devops service.
 *
 * Creates a new deployment pipeline.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDeployPipeline = new oci.devops.DeployPipeline("test_deploy_pipeline", {
 *     projectId: testProject.id,
 *     definedTags: {
 *         "foo-namespace.bar-key": "value",
 *     },
 *     deployPipelineParameters: {
 *         items: [{
 *             name: deployPipelineDeployPipelineParametersItemsName,
 *             defaultValue: deployPipelineDeployPipelineParametersItemsDefaultValue,
 *             description: deployPipelineDeployPipelineParametersItemsDescription,
 *         }],
 *     },
 *     description: deployPipelineDescription,
 *     displayName: deployPipelineDisplayName,
 *     freeformTags: {
 *         "bar-key": "value",
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * DeployPipelines can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:DevOps/deployPipeline:DeployPipeline test_deploy_pipeline "id"
 * ```
 */
export class DeployPipeline extends pulumi.CustomResource {
    /**
     * Get an existing DeployPipeline resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: DeployPipelineState, opts?: pulumi.CustomResourceOptions): DeployPipeline {
        return new DeployPipeline(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:DevOps/deployPipeline:DeployPipeline';

    /**
     * Returns true if the given object is an instance of DeployPipeline.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is DeployPipeline {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === DeployPipeline.__pulumiType;
    }

    /**
     * The OCID of the compartment where the pipeline is created.
     */
    public /*out*/ readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * List of all artifacts used in the pipeline.
     */
    public /*out*/ readonly deployPipelineArtifacts!: pulumi.Output<outputs.DevOps.DeployPipelineDeployPipelineArtifact[]>;
    /**
     * List of all environments used in the pipeline.
     */
    public /*out*/ readonly deployPipelineEnvironments!: pulumi.Output<outputs.DevOps.DeployPipelineDeployPipelineEnvironment[]>;
    /**
     * (Updatable) Specifies list of parameters present in the deployment pipeline. In case of Update operation, replaces existing parameters list. Merging with existing parameters is not supported.
     */
    public readonly deployPipelineParameters!: pulumi.Output<outputs.DevOps.DeployPipelineDeployPipelineParameters>;
    /**
     * (Updatable) Optional description about the deployment pipeline.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * (Updatable) Deployment pipeline display name. Avoid entering confidential information.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * The OCID of a project.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly projectId!: pulumi.Output<string>;
    /**
     * The current state of the deployment pipeline.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * Time the deployment pipeline was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * Time the deployment pipeline was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a DeployPipeline resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: DeployPipelineArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: DeployPipelineArgs | DeployPipelineState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as DeployPipelineState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["deployPipelineArtifacts"] = state ? state.deployPipelineArtifacts : undefined;
            resourceInputs["deployPipelineEnvironments"] = state ? state.deployPipelineEnvironments : undefined;
            resourceInputs["deployPipelineParameters"] = state ? state.deployPipelineParameters : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["projectId"] = state ? state.projectId : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as DeployPipelineArgs | undefined;
            if ((!args || args.projectId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'projectId'");
            }
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["deployPipelineParameters"] = args ? args.deployPipelineParameters : undefined;
            resourceInputs["description"] = args ? args.description : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["projectId"] = args ? args.projectId : undefined;
            resourceInputs["compartmentId"] = undefined /*out*/;
            resourceInputs["deployPipelineArtifacts"] = undefined /*out*/;
            resourceInputs["deployPipelineEnvironments"] = undefined /*out*/;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(DeployPipeline.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering DeployPipeline resources.
 */
export interface DeployPipelineState {
    /**
     * The OCID of the compartment where the pipeline is created.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * List of all artifacts used in the pipeline.
     */
    deployPipelineArtifacts?: pulumi.Input<pulumi.Input<inputs.DevOps.DeployPipelineDeployPipelineArtifact>[]>;
    /**
     * List of all environments used in the pipeline.
     */
    deployPipelineEnvironments?: pulumi.Input<pulumi.Input<inputs.DevOps.DeployPipelineDeployPipelineEnvironment>[]>;
    /**
     * (Updatable) Specifies list of parameters present in the deployment pipeline. In case of Update operation, replaces existing parameters list. Merging with existing parameters is not supported.
     */
    deployPipelineParameters?: pulumi.Input<inputs.DevOps.DeployPipelineDeployPipelineParameters>;
    /**
     * (Updatable) Optional description about the deployment pipeline.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) Deployment pipeline display name. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * The OCID of a project.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    projectId?: pulumi.Input<string>;
    /**
     * The current state of the deployment pipeline.
     */
    state?: pulumi.Input<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * Time the deployment pipeline was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * Time the deployment pipeline was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a DeployPipeline resource.
 */
export interface DeployPipelineArgs {
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Specifies list of parameters present in the deployment pipeline. In case of Update operation, replaces existing parameters list. Merging with existing parameters is not supported.
     */
    deployPipelineParameters?: pulumi.Input<inputs.DevOps.DeployPipelineDeployPipelineParameters>;
    /**
     * (Updatable) Optional description about the deployment pipeline.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) Deployment pipeline display name. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The OCID of a project.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    projectId: pulumi.Input<string>;
}
