// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Dataset resource in Oracle Cloud Infrastructure Data Labeling Service service.
 *
 * Gets a Dataset by identifier
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDataset = oci.DataLabellingService.getDataset({
 *     datasetId: testDatasetOciDataLabelingServiceDataset.id,
 * });
 * ```
 */
export function getDataset(args: GetDatasetArgs, opts?: pulumi.InvokeOptions): Promise<GetDatasetResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DataLabellingService/getDataset:getDataset", {
        "datasetId": args.datasetId,
    }, opts);
}

/**
 * A collection of arguments for invoking getDataset.
 */
export interface GetDatasetArgs {
    /**
     * Unique Dataset OCID
     */
    datasetId: string;
}

/**
 * A collection of values returned by getDataset.
 */
export interface GetDatasetResult {
    /**
     * A simple key-value pair that is applied without any predefined name, type, or scope. It exists for cross-compatibility only. For example: `{"bar-key": "value"}`
     */
    readonly additionalProperties: {[key: string]: string};
    /**
     * The annotation format name required for labeling records.
     */
    readonly annotationFormat: string;
    /**
     * The OCID of the compartment of the resource.
     */
    readonly compartmentId: string;
    /**
     * It specifies how to process the data. Supported formats include DOCUMENT, IMAGE, and TEXT.
     */
    readonly datasetFormatDetails: outputs.DataLabellingService.GetDatasetDatasetFormatDetail[];
    readonly datasetId: string;
    /**
     * This allows the customer to specify the source of the dataset.
     */
    readonly datasetSourceDetails: outputs.DataLabellingService.GetDatasetDatasetSourceDetail[];
    /**
     * The defined tags for this resource. Each key is predefined and scoped to a namespace. For example: `{"foo-namespace": {"bar-key": "value"}}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * A user provided description of the dataset
     */
    readonly description: string;
    /**
     * A user-friendly display name for the resource.
     */
    readonly displayName: string;
    /**
     * A simple key-value pair that is applied without any predefined name, type, or scope. It exists for cross-compatibility only. For example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The OCID of the Dataset.
     */
    readonly id: string;
    /**
     * Initial import dataset configuration. Allows user to create dataset from existing dataset files.
     */
    readonly initialImportDatasetConfigurations: outputs.DataLabellingService.GetDatasetInitialImportDatasetConfiguration[];
    /**
     * The initial generate records configuration. It generates records from the dataset's source.
     */
    readonly initialRecordGenerationConfigurations: outputs.DataLabellingService.GetDatasetInitialRecordGenerationConfiguration[];
    /**
     * An ordered collection of labels that are unique by name.
     */
    readonly labelSets: outputs.DataLabellingService.GetDatasetLabelSet[];
    /**
     * The labeling instructions for human labelers in rich text format
     */
    readonly labelingInstructions: string;
    /**
     * A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in FAILED or NEEDS_ATTENTION state.
     */
    readonly lifecycleDetails: string;
    /**
     * The sub-state of the dataset. IMPORT_DATASET - The dataset is being imported.
     */
    readonly lifecycleSubstate: string;
    /**
     * The state of a dataset. CREATING - The dataset is being created.  It will transition to ACTIVE when it is ready for labeling. ACTIVE   - The dataset is ready for labeling. UPDATING - The dataset is being updated.  It and its related resources may be unavailable for other updates until it returns to ACTIVE. NEEDS_ATTENTION - A dataset updation operation has failed due to validation or other errors and needs attention. DELETING - The dataset and its related resources are being deleted. DELETED  - The dataset has been deleted and is no longer available. FAILED   - The dataset has failed due to validation or other errors.
     */
    readonly state: string;
    /**
     * The date and time the resource was created, in the timestamp format defined by RFC3339.
     */
    readonly timeCreated: string;
    /**
     * The date and time the resource was last updated, in the timestamp format defined by RFC3339.
     */
    readonly timeUpdated: string;
}
/**
 * This data source provides details about a specific Dataset resource in Oracle Cloud Infrastructure Data Labeling Service service.
 *
 * Gets a Dataset by identifier
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDataset = oci.DataLabellingService.getDataset({
 *     datasetId: testDatasetOciDataLabelingServiceDataset.id,
 * });
 * ```
 */
export function getDatasetOutput(args: GetDatasetOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetDatasetResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DataLabellingService/getDataset:getDataset", {
        "datasetId": args.datasetId,
    }, opts);
}

/**
 * A collection of arguments for invoking getDataset.
 */
export interface GetDatasetOutputArgs {
    /**
     * Unique Dataset OCID
     */
    datasetId: pulumi.Input<string>;
}
