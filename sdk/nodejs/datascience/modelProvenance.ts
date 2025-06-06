// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Model Provenance resource in Oracle Cloud Infrastructure Data Science service.
 *
 * Creates provenance information for the specified model.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testModelProvenance = new oci.datascience.ModelProvenance("test_model_provenance", {
 *     modelId: testModel.id,
 *     gitBranch: modelProvenanceGitBranch,
 *     gitCommit: modelProvenanceGitCommit,
 *     repositoryUrl: modelProvenanceRepositoryUrl,
 *     scriptDir: modelProvenanceScriptDir,
 *     trainingId: testTraining.id,
 *     trainingScript: modelProvenanceTrainingScript,
 * });
 * ```
 *
 * ## Import
 *
 * ModelProvenances can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:DataScience/modelProvenance:ModelProvenance test_model_provenance "models/{modelId}/provenance"
 * ```
 */
export class ModelProvenance extends pulumi.CustomResource {
    /**
     * Get an existing ModelProvenance resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ModelProvenanceState, opts?: pulumi.CustomResourceOptions): ModelProvenance {
        return new ModelProvenance(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:DataScience/modelProvenance:ModelProvenance';

    /**
     * Returns true if the given object is an instance of ModelProvenance.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is ModelProvenance {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === ModelProvenance.__pulumiType;
    }

    /**
     * (Updatable) For model reproducibility purposes. Branch of the git repository associated with model training.
     */
    public readonly gitBranch!: pulumi.Output<string>;
    /**
     * (Updatable) For model reproducibility purposes. Commit ID of the git repository associated with model training.
     */
    public readonly gitCommit!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model.
     */
    public readonly modelId!: pulumi.Output<string>;
    /**
     * (Updatable) For model reproducibility purposes. URL of the git repository associated with model training.
     */
    public readonly repositoryUrl!: pulumi.Output<string>;
    /**
     * (Updatable) For model reproducibility purposes. Path to model artifacts.
     */
    public readonly scriptDir!: pulumi.Output<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a training session(Job or NotebookSession) in which the model was trained. It is used for model reproducibility purposes.
     */
    public readonly trainingId!: pulumi.Output<string>;
    /**
     * (Updatable) For model reproducibility purposes. Path to the python script or notebook in which the model was trained." 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly trainingScript!: pulumi.Output<string>;

    /**
     * Create a ModelProvenance resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ModelProvenanceArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ModelProvenanceArgs | ModelProvenanceState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ModelProvenanceState | undefined;
            resourceInputs["gitBranch"] = state ? state.gitBranch : undefined;
            resourceInputs["gitCommit"] = state ? state.gitCommit : undefined;
            resourceInputs["modelId"] = state ? state.modelId : undefined;
            resourceInputs["repositoryUrl"] = state ? state.repositoryUrl : undefined;
            resourceInputs["scriptDir"] = state ? state.scriptDir : undefined;
            resourceInputs["trainingId"] = state ? state.trainingId : undefined;
            resourceInputs["trainingScript"] = state ? state.trainingScript : undefined;
        } else {
            const args = argsOrState as ModelProvenanceArgs | undefined;
            if ((!args || args.modelId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'modelId'");
            }
            resourceInputs["gitBranch"] = args ? args.gitBranch : undefined;
            resourceInputs["gitCommit"] = args ? args.gitCommit : undefined;
            resourceInputs["modelId"] = args ? args.modelId : undefined;
            resourceInputs["repositoryUrl"] = args ? args.repositoryUrl : undefined;
            resourceInputs["scriptDir"] = args ? args.scriptDir : undefined;
            resourceInputs["trainingId"] = args ? args.trainingId : undefined;
            resourceInputs["trainingScript"] = args ? args.trainingScript : undefined;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(ModelProvenance.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering ModelProvenance resources.
 */
export interface ModelProvenanceState {
    /**
     * (Updatable) For model reproducibility purposes. Branch of the git repository associated with model training.
     */
    gitBranch?: pulumi.Input<string>;
    /**
     * (Updatable) For model reproducibility purposes. Commit ID of the git repository associated with model training.
     */
    gitCommit?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model.
     */
    modelId?: pulumi.Input<string>;
    /**
     * (Updatable) For model reproducibility purposes. URL of the git repository associated with model training.
     */
    repositoryUrl?: pulumi.Input<string>;
    /**
     * (Updatable) For model reproducibility purposes. Path to model artifacts.
     */
    scriptDir?: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a training session(Job or NotebookSession) in which the model was trained. It is used for model reproducibility purposes.
     */
    trainingId?: pulumi.Input<string>;
    /**
     * (Updatable) For model reproducibility purposes. Path to the python script or notebook in which the model was trained." 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    trainingScript?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a ModelProvenance resource.
 */
export interface ModelProvenanceArgs {
    /**
     * (Updatable) For model reproducibility purposes. Branch of the git repository associated with model training.
     */
    gitBranch?: pulumi.Input<string>;
    /**
     * (Updatable) For model reproducibility purposes. Commit ID of the git repository associated with model training.
     */
    gitCommit?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model.
     */
    modelId: pulumi.Input<string>;
    /**
     * (Updatable) For model reproducibility purposes. URL of the git repository associated with model training.
     */
    repositoryUrl?: pulumi.Input<string>;
    /**
     * (Updatable) For model reproducibility purposes. Path to model artifacts.
     */
    scriptDir?: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a training session(Job or NotebookSession) in which the model was trained. It is used for model reproducibility purposes.
     */
    trainingId?: pulumi.Input<string>;
    /**
     * (Updatable) For model reproducibility purposes. Path to the python script or notebook in which the model was trained." 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    trainingScript?: pulumi.Input<string>;
}
