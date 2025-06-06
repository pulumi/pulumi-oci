// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Media Workflow Job resource in Oracle Cloud Infrastructure Media Services service.
 *
 * Run the MediaWorkflow according to the given mediaWorkflow definition and configuration.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMediaWorkflowJob = new oci.mediaservices.MediaWorkflowJob("test_media_workflow_job", {
 *     compartmentId: compartmentId,
 *     workflowIdentifierType: mediaWorkflowJobWorkflowIdentifierType,
 *     definedTags: {
 *         "foo-namespace.bar-key": "value",
 *     },
 *     displayName: mediaWorkflowJobDisplayName,
 *     freeformTags: {
 *         "bar-key": "value",
 *     },
 *     locks: [{
 *         compartmentId: compartmentId,
 *         type: mediaWorkflowJobLocksType,
 *         message: mediaWorkflowJobLocksMessage,
 *         relatedResourceId: testResource.id,
 *         timeCreated: mediaWorkflowJobLocksTimeCreated,
 *     }],
 *     mediaWorkflowConfigurationIds: mediaWorkflowJobMediaWorkflowConfigurationIds,
 *     mediaWorkflowId: testMediaWorkflow.id,
 *     mediaWorkflowName: testMediaWorkflow.name,
 *     parameters: mediaWorkflowJobParameters,
 * });
 * ```
 *
 * ## Import
 *
 * MediaWorkflowJobs can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:MediaServices/mediaWorkflowJob:MediaWorkflowJob test_media_workflow_job "id"
 * ```
 */
export class MediaWorkflowJob extends pulumi.CustomResource {
    /**
     * Get an existing MediaWorkflowJob resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: MediaWorkflowJobState, opts?: pulumi.CustomResourceOptions): MediaWorkflowJob {
        return new MediaWorkflowJob(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:MediaServices/mediaWorkflowJob:MediaWorkflowJob';

    /**
     * Returns true if the given object is an instance of MediaWorkflowJob.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is MediaWorkflowJob {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === MediaWorkflowJob.__pulumiType;
    }

    /**
     * (Updatable) ID of the compartment in which the job should be created.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) Name of the Media Workflow Job. Does not have to be unique. Avoid entering confidential information.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    public readonly isLockOverride!: pulumi.Output<boolean>;
    /**
     * The lifecycle details of MediaWorkflowJob task.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * Locks associated with this resource.
     */
    public readonly locks!: pulumi.Output<outputs.MediaServices.MediaWorkflowJobLock[]>;
    /**
     * Configurations to be applied to this run of the workflow.
     */
    public readonly mediaWorkflowConfigurationIds!: pulumi.Output<string[]>;
    /**
     * OCID of the MediaWorkflow that should be run.
     */
    public readonly mediaWorkflowId!: pulumi.Output<string>;
    /**
     * Name of the system MediaWorkflow that should be run.
     */
    public readonly mediaWorkflowName!: pulumi.Output<string>;
    /**
     * A list of JobOutput for the workflowJob.
     */
    public /*out*/ readonly outputs!: pulumi.Output<outputs.MediaServices.MediaWorkflowJobOutput[]>;
    /**
     * Parameters that override parameters specified in MediaWorkflowTaskDeclarations, the MediaWorkflow, the MediaWorkflow's MediaWorkflowConfigurations and the MediaWorkflowConfigurations of this MediaWorkflowJob. The parameters are given as JSON. The top level and 2nd level elements must be JSON objects (vs arrays, scalars, etc). The top level keys refer to a task's key and the 2nd level keys refer to a parameter's name.
     */
    public readonly parameters!: pulumi.Output<string>;
    /**
     * A JSON representation of the job as it will be run by the system. All the task declarations, configurations and parameters are merged. Parameter values are all fully resolved.
     */
    public /*out*/ readonly runnable!: pulumi.Output<string>;
    /**
     * The current state of the MediaWorkflowJob task.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * Status of each task.
     */
    public /*out*/ readonly taskLifecycleStates!: pulumi.Output<outputs.MediaServices.MediaWorkflowJobTaskLifecycleState[]>;
    /**
     * Creation time of the job. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * Time when the job finished. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeEnded!: pulumi.Output<string>;
    /**
     * Time when the job started to execute. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeStarted!: pulumi.Output<string>;
    /**
     * Updated time of the job. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;
    /**
     * Discriminate identification of a workflow by name versus a workflow by ID.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly workflowIdentifierType!: pulumi.Output<string>;

    /**
     * Create a MediaWorkflowJob resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: MediaWorkflowJobArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: MediaWorkflowJobArgs | MediaWorkflowJobState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as MediaWorkflowJobState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["isLockOverride"] = state ? state.isLockOverride : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["locks"] = state ? state.locks : undefined;
            resourceInputs["mediaWorkflowConfigurationIds"] = state ? state.mediaWorkflowConfigurationIds : undefined;
            resourceInputs["mediaWorkflowId"] = state ? state.mediaWorkflowId : undefined;
            resourceInputs["mediaWorkflowName"] = state ? state.mediaWorkflowName : undefined;
            resourceInputs["outputs"] = state ? state.outputs : undefined;
            resourceInputs["parameters"] = state ? state.parameters : undefined;
            resourceInputs["runnable"] = state ? state.runnable : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["taskLifecycleStates"] = state ? state.taskLifecycleStates : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeEnded"] = state ? state.timeEnded : undefined;
            resourceInputs["timeStarted"] = state ? state.timeStarted : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
            resourceInputs["workflowIdentifierType"] = state ? state.workflowIdentifierType : undefined;
        } else {
            const args = argsOrState as MediaWorkflowJobArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.workflowIdentifierType === undefined) && !opts.urn) {
                throw new Error("Missing required property 'workflowIdentifierType'");
            }
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["isLockOverride"] = args ? args.isLockOverride : undefined;
            resourceInputs["locks"] = args ? args.locks : undefined;
            resourceInputs["mediaWorkflowConfigurationIds"] = args ? args.mediaWorkflowConfigurationIds : undefined;
            resourceInputs["mediaWorkflowId"] = args ? args.mediaWorkflowId : undefined;
            resourceInputs["mediaWorkflowName"] = args ? args.mediaWorkflowName : undefined;
            resourceInputs["parameters"] = args ? args.parameters : undefined;
            resourceInputs["workflowIdentifierType"] = args ? args.workflowIdentifierType : undefined;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["outputs"] = undefined /*out*/;
            resourceInputs["runnable"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["taskLifecycleStates"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeEnded"] = undefined /*out*/;
            resourceInputs["timeStarted"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(MediaWorkflowJob.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering MediaWorkflowJob resources.
 */
export interface MediaWorkflowJobState {
    /**
     * (Updatable) ID of the compartment in which the job should be created.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Name of the Media Workflow Job. Does not have to be unique. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    isLockOverride?: pulumi.Input<boolean>;
    /**
     * The lifecycle details of MediaWorkflowJob task.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * Locks associated with this resource.
     */
    locks?: pulumi.Input<pulumi.Input<inputs.MediaServices.MediaWorkflowJobLock>[]>;
    /**
     * Configurations to be applied to this run of the workflow.
     */
    mediaWorkflowConfigurationIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * OCID of the MediaWorkflow that should be run.
     */
    mediaWorkflowId?: pulumi.Input<string>;
    /**
     * Name of the system MediaWorkflow that should be run.
     */
    mediaWorkflowName?: pulumi.Input<string>;
    /**
     * A list of JobOutput for the workflowJob.
     */
    outputs?: pulumi.Input<pulumi.Input<inputs.MediaServices.MediaWorkflowJobOutput>[]>;
    /**
     * Parameters that override parameters specified in MediaWorkflowTaskDeclarations, the MediaWorkflow, the MediaWorkflow's MediaWorkflowConfigurations and the MediaWorkflowConfigurations of this MediaWorkflowJob. The parameters are given as JSON. The top level and 2nd level elements must be JSON objects (vs arrays, scalars, etc). The top level keys refer to a task's key and the 2nd level keys refer to a parameter's name.
     */
    parameters?: pulumi.Input<string>;
    /**
     * A JSON representation of the job as it will be run by the system. All the task declarations, configurations and parameters are merged. Parameter values are all fully resolved.
     */
    runnable?: pulumi.Input<string>;
    /**
     * The current state of the MediaWorkflowJob task.
     */
    state?: pulumi.Input<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * Status of each task.
     */
    taskLifecycleStates?: pulumi.Input<pulumi.Input<inputs.MediaServices.MediaWorkflowJobTaskLifecycleState>[]>;
    /**
     * Creation time of the job. An RFC3339 formatted datetime string.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * Time when the job finished. An RFC3339 formatted datetime string.
     */
    timeEnded?: pulumi.Input<string>;
    /**
     * Time when the job started to execute. An RFC3339 formatted datetime string.
     */
    timeStarted?: pulumi.Input<string>;
    /**
     * Updated time of the job. An RFC3339 formatted datetime string.
     */
    timeUpdated?: pulumi.Input<string>;
    /**
     * Discriminate identification of a workflow by name versus a workflow by ID.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    workflowIdentifierType?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a MediaWorkflowJob resource.
 */
export interface MediaWorkflowJobArgs {
    /**
     * (Updatable) ID of the compartment in which the job should be created.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Name of the Media Workflow Job. Does not have to be unique. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    isLockOverride?: pulumi.Input<boolean>;
    /**
     * Locks associated with this resource.
     */
    locks?: pulumi.Input<pulumi.Input<inputs.MediaServices.MediaWorkflowJobLock>[]>;
    /**
     * Configurations to be applied to this run of the workflow.
     */
    mediaWorkflowConfigurationIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * OCID of the MediaWorkflow that should be run.
     */
    mediaWorkflowId?: pulumi.Input<string>;
    /**
     * Name of the system MediaWorkflow that should be run.
     */
    mediaWorkflowName?: pulumi.Input<string>;
    /**
     * Parameters that override parameters specified in MediaWorkflowTaskDeclarations, the MediaWorkflow, the MediaWorkflow's MediaWorkflowConfigurations and the MediaWorkflowConfigurations of this MediaWorkflowJob. The parameters are given as JSON. The top level and 2nd level elements must be JSON objects (vs arrays, scalars, etc). The top level keys refer to a task's key and the 2nd level keys refer to a parameter's name.
     */
    parameters?: pulumi.Input<string>;
    /**
     * Discriminate identification of a workflow by name versus a workflow by ID.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    workflowIdentifierType: pulumi.Input<string>;
}
