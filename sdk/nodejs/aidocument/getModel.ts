// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Model resource in Oracle Cloud Infrastructure Ai Document service.
 *
 * Get a model by identifier.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testModel = oci.AiDocument.getModel({
 *     modelId: oci_ai_document_model.test_model.id,
 * });
 * ```
 */
export function getModel(args: GetModelArgs, opts?: pulumi.InvokeOptions): Promise<GetModelResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:AiDocument/getModel:getModel", {
        "modelId": args.modelId,
    }, opts);
}

/**
 * A collection of arguments for invoking getModel.
 */
export interface GetModelArgs {
    /**
     * A unique model identifier.
     */
    modelId: string;
}

/**
 * A collection of values returned by getModel.
 */
export interface GetModelResult {
    /**
     * The compartment identifier.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For example: `{"foo-namespace": {"bar-key": "value"}}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * An optional description of the model.
     */
    readonly description: string;
    /**
     * A human-friendly name for the model, which can be changed.
     */
    readonly displayName: string;
    /**
     * A simple key-value pair that is applied without any predefined name, type, or scope. It exists for cross-compatibility only. For example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * A unique identifier that is immutable after creation.
     */
    readonly id: string;
    /**
     * Set to true when experimenting with a new model type or dataset, so model training is quick, with a predefined low number of passes through the training data.
     */
    readonly isQuickMode: boolean;
    /**
     * The collection of labels used to train the custom model.
     */
    readonly labels: string[];
    /**
     * A message describing the current state in more detail, that can provide actionable information if training failed.
     */
    readonly lifecycleDetails: string;
    /**
     * The maximum model training time in hours, expressed as a decimal fraction.
     */
    readonly maxTrainingTimeInHours: number;
    /**
     * Trained Model Metrics.
     */
    readonly metrics: outputs.AiDocument.GetModelMetric[];
    readonly modelId: string;
    /**
     * The type of the Document model.
     */
    readonly modelType: string;
    /**
     * The version of the model.
     */
    readonly modelVersion: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project that contains the model.
     */
    readonly projectId: string;
    /**
     * The current state of the model.
     */
    readonly state: string;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. For example: `{"orcl-cloud": {"free-tier-retained": "true"}}`
     */
    readonly systemTags: {[key: string]: any};
    /**
     * The base entity which is the input for creating and training a model.
     */
    readonly testingDatasets: outputs.AiDocument.GetModelTestingDataset[];
    /**
     * When the model was created, as an RFC3339 datetime string.
     */
    readonly timeCreated: string;
    /**
     * When the model was updated, as an RFC3339 datetime string.
     */
    readonly timeUpdated: string;
    /**
     * The total hours actually used for model training.
     */
    readonly trainedTimeInHours: number;
    /**
     * The base entity which is the input for creating and training a model.
     */
    readonly trainingDatasets: outputs.AiDocument.GetModelTrainingDataset[];
    /**
     * The base entity which is the input for creating and training a model.
     */
    readonly validationDatasets: outputs.AiDocument.GetModelValidationDataset[];
}
/**
 * This data source provides details about a specific Model resource in Oracle Cloud Infrastructure Ai Document service.
 *
 * Get a model by identifier.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testModel = oci.AiDocument.getModel({
 *     modelId: oci_ai_document_model.test_model.id,
 * });
 * ```
 */
export function getModelOutput(args: GetModelOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetModelResult> {
    return pulumi.output(args).apply((a: any) => getModel(a, opts))
}

/**
 * A collection of arguments for invoking getModel.
 */
export interface GetModelOutputArgs {
    /**
     * A unique model identifier.
     */
    modelId: pulumi.Input<string>;
}