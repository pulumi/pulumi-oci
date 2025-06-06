// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Pipeline resource in Oracle Cloud Infrastructure Data Science service.
 *
 * Creates a new Pipeline.
 *
 * ## Import
 *
 * Pipelines can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:DataScience/pipeline:Pipeline test_pipeline "id"
 * ```
 */
export class Pipeline extends pulumi.CustomResource {
    /**
     * Get an existing Pipeline resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: PipelineState, opts?: pulumi.CustomResourceOptions): Pipeline {
        return new Pipeline(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:DataScience/pipeline:Pipeline';

    /**
     * Returns true if the given object is an instance of Pipeline.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is Pipeline {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === Pipeline.__pulumiType;
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the pipeline.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) The configuration details of a pipeline.
     */
    public readonly configurationDetails!: pulumi.Output<outputs.DataScience.PipelineConfigurationDetails>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the pipeline.
     */
    public /*out*/ readonly createdBy!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    public readonly deleteRelatedPipelineRuns!: pulumi.Output<boolean | undefined>;
    /**
     * (Updatable) A short description of the pipeline.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * (Updatable) A user-friendly display name for the resource.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) The infrastructure configuration details of a pipeline or a step.
     */
    public readonly infrastructureConfigurationDetails!: pulumi.Output<outputs.DataScience.PipelineInfrastructureConfigurationDetails>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in 'Failed' state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * (Updatable) The pipeline log configuration details.
     */
    public readonly logConfigurationDetails!: pulumi.Output<outputs.DataScience.PipelineLogConfigurationDetails>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the pipeline with.
     */
    public readonly projectId!: pulumi.Output<string>;
    /**
     * The current state of the pipeline.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    public readonly stepArtifacts!: pulumi.Output<outputs.DataScience.PipelineStepArtifact[]>;
    /**
     * (Updatable) Array of step details for each step.
     */
    public readonly stepDetails!: pulumi.Output<outputs.DataScience.PipelineStepDetail[]>;
    /**
     * (Updatable) The storage mount details to mount to the instance running the pipeline step.
     */
    public readonly storageMountConfigurationDetailsLists!: pulumi.Output<outputs.DataScience.PipelineStorageMountConfigurationDetailsList[]>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The date and time the resource was created in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2020-08-06T21:10:29.41Z
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The date and time the resource was updated in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2020-08-06T21:10:29.41Z
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a Pipeline resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: PipelineArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: PipelineArgs | PipelineState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as PipelineState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["configurationDetails"] = state ? state.configurationDetails : undefined;
            resourceInputs["createdBy"] = state ? state.createdBy : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["deleteRelatedPipelineRuns"] = state ? state.deleteRelatedPipelineRuns : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["infrastructureConfigurationDetails"] = state ? state.infrastructureConfigurationDetails : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["logConfigurationDetails"] = state ? state.logConfigurationDetails : undefined;
            resourceInputs["projectId"] = state ? state.projectId : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["stepArtifacts"] = state ? state.stepArtifacts : undefined;
            resourceInputs["stepDetails"] = state ? state.stepDetails : undefined;
            resourceInputs["storageMountConfigurationDetailsLists"] = state ? state.storageMountConfigurationDetailsLists : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as PipelineArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.projectId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'projectId'");
            }
            if ((!args || args.stepDetails === undefined) && !opts.urn) {
                throw new Error("Missing required property 'stepDetails'");
            }
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["configurationDetails"] = args ? args.configurationDetails : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["deleteRelatedPipelineRuns"] = args ? args.deleteRelatedPipelineRuns : undefined;
            resourceInputs["description"] = args ? args.description : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["infrastructureConfigurationDetails"] = args ? args.infrastructureConfigurationDetails : undefined;
            resourceInputs["logConfigurationDetails"] = args ? args.logConfigurationDetails : undefined;
            resourceInputs["projectId"] = args ? args.projectId : undefined;
            resourceInputs["stepArtifacts"] = args ? args.stepArtifacts : undefined;
            resourceInputs["stepDetails"] = args ? args.stepDetails : undefined;
            resourceInputs["storageMountConfigurationDetailsLists"] = args ? args.storageMountConfigurationDetailsLists : undefined;
            resourceInputs["createdBy"] = undefined /*out*/;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(Pipeline.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering Pipeline resources.
 */
export interface PipelineState {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the pipeline.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) The configuration details of a pipeline.
     */
    configurationDetails?: pulumi.Input<inputs.DataScience.PipelineConfigurationDetails>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the pipeline.
     */
    createdBy?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    deleteRelatedPipelineRuns?: pulumi.Input<boolean>;
    /**
     * (Updatable) A short description of the pipeline.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) A user-friendly display name for the resource.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) The infrastructure configuration details of a pipeline or a step.
     */
    infrastructureConfigurationDetails?: pulumi.Input<inputs.DataScience.PipelineInfrastructureConfigurationDetails>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in 'Failed' state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * (Updatable) The pipeline log configuration details.
     */
    logConfigurationDetails?: pulumi.Input<inputs.DataScience.PipelineLogConfigurationDetails>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the pipeline with.
     */
    projectId?: pulumi.Input<string>;
    /**
     * The current state of the pipeline.
     */
    state?: pulumi.Input<string>;
    stepArtifacts?: pulumi.Input<pulumi.Input<inputs.DataScience.PipelineStepArtifact>[]>;
    /**
     * (Updatable) Array of step details for each step.
     */
    stepDetails?: pulumi.Input<pulumi.Input<inputs.DataScience.PipelineStepDetail>[]>;
    /**
     * (Updatable) The storage mount details to mount to the instance running the pipeline step.
     */
    storageMountConfigurationDetailsLists?: pulumi.Input<pulumi.Input<inputs.DataScience.PipelineStorageMountConfigurationDetailsList>[]>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The date and time the resource was created in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2020-08-06T21:10:29.41Z
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The date and time the resource was updated in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2020-08-06T21:10:29.41Z
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a Pipeline resource.
 */
export interface PipelineArgs {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the pipeline.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) The configuration details of a pipeline.
     */
    configurationDetails?: pulumi.Input<inputs.DataScience.PipelineConfigurationDetails>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    deleteRelatedPipelineRuns?: pulumi.Input<boolean>;
    /**
     * (Updatable) A short description of the pipeline.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) A user-friendly display name for the resource.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) The infrastructure configuration details of a pipeline or a step.
     */
    infrastructureConfigurationDetails?: pulumi.Input<inputs.DataScience.PipelineInfrastructureConfigurationDetails>;
    /**
     * (Updatable) The pipeline log configuration details.
     */
    logConfigurationDetails?: pulumi.Input<inputs.DataScience.PipelineLogConfigurationDetails>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the pipeline with.
     */
    projectId: pulumi.Input<string>;
    stepArtifacts?: pulumi.Input<pulumi.Input<inputs.DataScience.PipelineStepArtifact>[]>;
    /**
     * (Updatable) Array of step details for each step.
     */
    stepDetails: pulumi.Input<pulumi.Input<inputs.DataScience.PipelineStepDetail>[]>;
    /**
     * (Updatable) The storage mount details to mount to the instance running the pipeline step.
     */
    storageMountConfigurationDetailsLists?: pulumi.Input<pulumi.Input<inputs.DataScience.PipelineStorageMountConfigurationDetailsList>[]>;
}
