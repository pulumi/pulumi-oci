// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Media Workflow resource in Oracle Cloud Infrastructure Media Services service.
 *
 * Creates a new MediaWorkflow.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMediaWorkflow = new oci.mediaservices.MediaWorkflow("testMediaWorkflow", {
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.media_workflow_display_name,
 *     definedTags: {
 *         "foo-namespace.bar-key": "value",
 *     },
 *     freeformTags: {
 *         "bar-key": "value",
 *     },
 *     mediaWorkflowConfigurationIds: _var.media_workflow_media_workflow_configuration_ids,
 *     parameters: _var.media_workflow_parameters,
 *     tasks: [{
 *         key: _var.media_workflow_tasks_key,
 *         parameters: _var.media_workflow_tasks_parameters,
 *         type: _var.media_workflow_tasks_type,
 *         version: _var.media_workflow_tasks_version,
 *         enableParameterReference: _var.media_workflow_tasks_enable_parameter_reference,
 *         enableWhenReferencedParameterEquals: _var.media_workflow_tasks_enable_when_referenced_parameter_equals,
 *         prerequisites: _var.media_workflow_tasks_prerequisites,
 *     }],
 * });
 * ```
 *
 * ## Import
 *
 * MediaWorkflows can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:MediaServices/mediaWorkflow:MediaWorkflow test_media_workflow "id"
 * ```
 */
export class MediaWorkflow extends pulumi.CustomResource {
    /**
     * Get an existing MediaWorkflow resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: MediaWorkflowState, opts?: pulumi.CustomResourceOptions): MediaWorkflow {
        return new MediaWorkflow(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:MediaServices/mediaWorkflow:MediaWorkflow';

    /**
     * Returns true if the given object is an instance of MediaWorkflow.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is MediaWorkflow {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === MediaWorkflow.__pulumiType;
    }

    /**
     * (Updatable) Compartment Identifier.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) Name for the MediaWorkflow. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    public /*out*/ readonly lifecyleDetails!: pulumi.Output<string>;
    /**
     * (Updatable) Configurations to be applied to all the jobs for this workflow. Parameters in these configurations are overridden by parameters in the MediaWorkflowConfigurations of the MediaWorkflowJob and the parameters of the MediaWorkflowJob.
     */
    public readonly mediaWorkflowConfigurationIds!: pulumi.Output<string[]>;
    /**
     * (Updatable) Data specifiying how this task is to be run. The data is a JSON object that must conform to the JSON Schema specified by the parameters of the MediaWorkflowTaskDeclaration this task references. The parameters may contain values or references to other parameters.
     */
    public readonly parameters!: pulumi.Output<string>;
    /**
     * The current state of the MediaWorkflow.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) The processing to be done in this workflow. Each key of the MediaWorkflowTasks in this array must be unique within the array. The order of tasks given here will be preserved.
     */
    public readonly tasks!: pulumi.Output<outputs.MediaServices.MediaWorkflowTask[]>;
    /**
     * The time when the MediaWorkflow was created. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The time when the MediaWorkflow was updated. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;
    /**
     * (Updatable) The version of the MediaWorkflowTaskDeclaration.
     */
    public /*out*/ readonly version!: pulumi.Output<string>;

    /**
     * Create a MediaWorkflow resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: MediaWorkflowArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: MediaWorkflowArgs | MediaWorkflowState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as MediaWorkflowState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["lifecyleDetails"] = state ? state.lifecyleDetails : undefined;
            resourceInputs["mediaWorkflowConfigurationIds"] = state ? state.mediaWorkflowConfigurationIds : undefined;
            resourceInputs["parameters"] = state ? state.parameters : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["tasks"] = state ? state.tasks : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
            resourceInputs["version"] = state ? state.version : undefined;
        } else {
            const args = argsOrState as MediaWorkflowArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["mediaWorkflowConfigurationIds"] = args ? args.mediaWorkflowConfigurationIds : undefined;
            resourceInputs["parameters"] = args ? args.parameters : undefined;
            resourceInputs["tasks"] = args ? args.tasks : undefined;
            resourceInputs["lifecyleDetails"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
            resourceInputs["version"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(MediaWorkflow.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering MediaWorkflow resources.
 */
export interface MediaWorkflowState {
    /**
     * (Updatable) Compartment Identifier.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Name for the MediaWorkflow. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    lifecyleDetails?: pulumi.Input<string>;
    /**
     * (Updatable) Configurations to be applied to all the jobs for this workflow. Parameters in these configurations are overridden by parameters in the MediaWorkflowConfigurations of the MediaWorkflowJob and the parameters of the MediaWorkflowJob.
     */
    mediaWorkflowConfigurationIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * (Updatable) Data specifiying how this task is to be run. The data is a JSON object that must conform to the JSON Schema specified by the parameters of the MediaWorkflowTaskDeclaration this task references. The parameters may contain values or references to other parameters.
     */
    parameters?: pulumi.Input<string>;
    /**
     * The current state of the MediaWorkflow.
     */
    state?: pulumi.Input<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The processing to be done in this workflow. Each key of the MediaWorkflowTasks in this array must be unique within the array. The order of tasks given here will be preserved.
     */
    tasks?: pulumi.Input<pulumi.Input<inputs.MediaServices.MediaWorkflowTask>[]>;
    /**
     * The time when the MediaWorkflow was created. An RFC3339 formatted datetime string.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The time when the MediaWorkflow was updated. An RFC3339 formatted datetime string.
     */
    timeUpdated?: pulumi.Input<string>;
    /**
     * (Updatable) The version of the MediaWorkflowTaskDeclaration.
     */
    version?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a MediaWorkflow resource.
 */
export interface MediaWorkflowArgs {
    /**
     * (Updatable) Compartment Identifier.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Name for the MediaWorkflow. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    displayName: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Configurations to be applied to all the jobs for this workflow. Parameters in these configurations are overridden by parameters in the MediaWorkflowConfigurations of the MediaWorkflowJob and the parameters of the MediaWorkflowJob.
     */
    mediaWorkflowConfigurationIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * (Updatable) Data specifiying how this task is to be run. The data is a JSON object that must conform to the JSON Schema specified by the parameters of the MediaWorkflowTaskDeclaration this task references. The parameters may contain values or references to other parameters.
     */
    parameters?: pulumi.Input<string>;
    /**
     * (Updatable) The processing to be done in this workflow. Each key of the MediaWorkflowTasks in this array must be unique within the array. The order of tasks given here will be preserved.
     */
    tasks?: pulumi.Input<pulumi.Input<inputs.MediaServices.MediaWorkflowTask>[]>;
}