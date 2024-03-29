// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataLabellingService;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.DataLabellingService.DatasetArgs;
import com.pulumi.oci.DataLabellingService.inputs.DatasetState;
import com.pulumi.oci.DataLabellingService.outputs.DatasetDatasetFormatDetails;
import com.pulumi.oci.DataLabellingService.outputs.DatasetDatasetSourceDetails;
import com.pulumi.oci.DataLabellingService.outputs.DatasetInitialImportDatasetConfiguration;
import com.pulumi.oci.DataLabellingService.outputs.DatasetInitialRecordGenerationConfiguration;
import com.pulumi.oci.DataLabellingService.outputs.DatasetLabelSet;
import com.pulumi.oci.Utilities;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Dataset resource in Oracle Cloud Infrastructure Data Labeling Service service.
 * 
 * Creates a new Dataset.
 * 
 * ## Example Usage
 * 
 * &lt;!--Start PulumiCodeChooser --&gt;
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.DataLabellingService.Dataset;
 * import com.pulumi.oci.DataLabellingService.DatasetArgs;
 * import com.pulumi.oci.DataLabellingService.inputs.DatasetDatasetFormatDetailsArgs;
 * import com.pulumi.oci.DataLabellingService.inputs.DatasetDatasetFormatDetailsTextFileTypeMetadataArgs;
 * import com.pulumi.oci.DataLabellingService.inputs.DatasetDatasetSourceDetailsArgs;
 * import com.pulumi.oci.DataLabellingService.inputs.DatasetLabelSetArgs;
 * import com.pulumi.oci.DataLabellingService.inputs.DatasetInitialImportDatasetConfigurationArgs;
 * import com.pulumi.oci.DataLabellingService.inputs.DatasetInitialImportDatasetConfigurationImportFormatArgs;
 * import com.pulumi.oci.DataLabellingService.inputs.DatasetInitialImportDatasetConfigurationImportMetadataPathArgs;
 * import com.pulumi.oci.DataLabellingService.inputs.DatasetInitialRecordGenerationConfigurationArgs;
 * import java.util.List;
 * import java.util.ArrayList;
 * import java.util.Map;
 * import java.io.File;
 * import java.nio.file.Files;
 * import java.nio.file.Paths;
 * 
 * public class App {
 *     public static void main(String[] args) {
 *         Pulumi.run(App::stack);
 *     }
 * 
 *     public static void stack(Context ctx) {
 *         var testDataset = new Dataset(&#34;testDataset&#34;, DatasetArgs.builder()        
 *             .annotationFormat(var_.dataset_annotation_format())
 *             .compartmentId(var_.compartment_id())
 *             .datasetFormatDetails(DatasetDatasetFormatDetailsArgs.builder()
 *                 .formatType(var_.dataset_dataset_format_details_format_type())
 *                 .textFileTypeMetadata(DatasetDatasetFormatDetailsTextFileTypeMetadataArgs.builder()
 *                     .columnIndex(var_.dataset_dataset_format_details_text_file_type_metadata_column_index())
 *                     .formatType(var_.dataset_dataset_format_details_text_file_type_metadata_format_type())
 *                     .columnDelimiter(var_.dataset_dataset_format_details_text_file_type_metadata_column_delimiter())
 *                     .columnName(var_.dataset_dataset_format_details_text_file_type_metadata_column_name())
 *                     .escapeCharacter(var_.dataset_dataset_format_details_text_file_type_metadata_escape_character())
 *                     .lineDelimiter(var_.dataset_dataset_format_details_text_file_type_metadata_line_delimiter())
 *                     .build())
 *                 .build())
 *             .datasetSourceDetails(DatasetDatasetSourceDetailsArgs.builder()
 *                 .bucket(var_.dataset_dataset_source_details_bucket())
 *                 .namespace(var_.dataset_dataset_source_details_namespace())
 *                 .sourceType(var_.dataset_dataset_source_details_source_type())
 *                 .prefix(var_.dataset_dataset_source_details_prefix())
 *                 .build())
 *             .labelSet(DatasetLabelSetArgs.builder()
 *                 .items(DatasetLabelSetItemArgs.builder()
 *                     .name(var_.dataset_label_set_items_name())
 *                     .build())
 *                 .build())
 *             .definedTags(var_.dataset_defined_tags())
 *             .description(var_.dataset_description())
 *             .displayName(var_.dataset_display_name())
 *             .freeformTags(var_.dataset_freeform_tags())
 *             .initialImportDatasetConfiguration(DatasetInitialImportDatasetConfigurationArgs.builder()
 *                 .importFormat(DatasetInitialImportDatasetConfigurationImportFormatArgs.builder()
 *                     .name(var_.dataset_initial_import_dataset_configuration_import_format_name())
 *                     .version(var_.dataset_initial_import_dataset_configuration_import_format_version())
 *                     .build())
 *                 .importMetadataPath(DatasetInitialImportDatasetConfigurationImportMetadataPathArgs.builder()
 *                     .bucket(var_.dataset_initial_import_dataset_configuration_import_metadata_path_bucket())
 *                     .namespace(var_.dataset_initial_import_dataset_configuration_import_metadata_path_namespace())
 *                     .path(var_.dataset_initial_import_dataset_configuration_import_metadata_path_path())
 *                     .sourceType(var_.dataset_initial_import_dataset_configuration_import_metadata_path_source_type())
 *                     .build())
 *                 .build())
 *             .initialRecordGenerationConfiguration()
 *             .labelingInstructions(var_.dataset_labeling_instructions())
 *             .build());
 * 
 *     }
 * }
 * ```
 * &lt;!--End PulumiCodeChooser --&gt;
 * 
 * ## Import
 * 
 * Datasets can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:DataLabellingService/dataset:Dataset test_dataset &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:DataLabellingService/dataset:Dataset")
public class Dataset extends com.pulumi.resources.CustomResource {
    /**
     * A simple key-value pair that is applied without any predefined name, type, or scope. It exists for cross-compatibility only. For example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="additionalProperties", refs={Map.class,String.class,Object.class}, tree="[0,1,2]")
    private Output<Map<String,Object>> additionalProperties;

    /**
     * @return A simple key-value pair that is applied without any predefined name, type, or scope. It exists for cross-compatibility only. For example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,Object>> additionalProperties() {
        return this.additionalProperties;
    }
    /**
     * The annotation format name required for labeling records.
     * 
     */
    @Export(name="annotationFormat", refs={String.class}, tree="[0]")
    private Output<String> annotationFormat;

    /**
     * @return The annotation format name required for labeling records.
     * 
     */
    public Output<String> annotationFormat() {
        return this.annotationFormat;
    }
    /**
     * (Updatable) The OCID of the compartment of the resource.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the compartment of the resource.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * It specifies how to process the data. Supported formats include DOCUMENT, IMAGE, and TEXT.
     * 
     */
    @Export(name="datasetFormatDetails", refs={DatasetDatasetFormatDetails.class}, tree="[0]")
    private Output<DatasetDatasetFormatDetails> datasetFormatDetails;

    /**
     * @return It specifies how to process the data. Supported formats include DOCUMENT, IMAGE, and TEXT.
     * 
     */
    public Output<DatasetDatasetFormatDetails> datasetFormatDetails() {
        return this.datasetFormatDetails;
    }
    /**
     * This allows the customer to specify the source of the dataset.
     * 
     */
    @Export(name="datasetSourceDetails", refs={DatasetDatasetSourceDetails.class}, tree="[0]")
    private Output<DatasetDatasetSourceDetails> datasetSourceDetails;

    /**
     * @return This allows the customer to specify the source of the dataset.
     * 
     */
    public Output<DatasetDatasetSourceDetails> datasetSourceDetails() {
        return this.datasetSourceDetails;
    }
    /**
     * (Updatable) The defined tags for this resource. Each key is predefined and scoped to a namespace. For example: `{&#34;foo-namespace&#34;: {&#34;bar-key&#34;: &#34;value&#34;}}`
     * 
     */
    @Export(name="definedTags", refs={Map.class,String.class,Object.class}, tree="[0,1,2]")
    private Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) The defined tags for this resource. Each key is predefined and scoped to a namespace. For example: `{&#34;foo-namespace&#34;: {&#34;bar-key&#34;: &#34;value&#34;}}`
     * 
     */
    public Output<Map<String,Object>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) A user provided description of the dataset
     * 
     */
    @Export(name="description", refs={String.class}, tree="[0]")
    private Output<String> description;

    /**
     * @return (Updatable) A user provided description of the dataset
     * 
     */
    public Output<String> description() {
        return this.description;
    }
    /**
     * (Updatable) A user-friendly display name for the resource.
     * 
     */
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly display name for the resource.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * (Updatable) A simple key-value pair that is applied without any predefined name, type, or scope. It exists for cross-compatibility only. For example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="freeformTags", refs={Map.class,String.class,Object.class}, tree="[0,1,2]")
    private Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) A simple key-value pair that is applied without any predefined name, type, or scope. It exists for cross-compatibility only. For example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,Object>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * Initial import dataset configuration. Allows user to create dataset from existing dataset files.
     * 
     */
    @Export(name="initialImportDatasetConfiguration", refs={DatasetInitialImportDatasetConfiguration.class}, tree="[0]")
    private Output<DatasetInitialImportDatasetConfiguration> initialImportDatasetConfiguration;

    /**
     * @return Initial import dataset configuration. Allows user to create dataset from existing dataset files.
     * 
     */
    public Output<DatasetInitialImportDatasetConfiguration> initialImportDatasetConfiguration() {
        return this.initialImportDatasetConfiguration;
    }
    /**
     * The initial generate records configuration. It generates records from the dataset&#39;s source.
     * 
     */
    @Export(name="initialRecordGenerationConfiguration", refs={DatasetInitialRecordGenerationConfiguration.class}, tree="[0]")
    private Output<DatasetInitialRecordGenerationConfiguration> initialRecordGenerationConfiguration;

    /**
     * @return The initial generate records configuration. It generates records from the dataset&#39;s source.
     * 
     */
    public Output<DatasetInitialRecordGenerationConfiguration> initialRecordGenerationConfiguration() {
        return this.initialRecordGenerationConfiguration;
    }
    /**
     * An ordered collection of labels that are unique by name.
     * 
     */
    @Export(name="labelSet", refs={DatasetLabelSet.class}, tree="[0]")
    private Output<DatasetLabelSet> labelSet;

    /**
     * @return An ordered collection of labels that are unique by name.
     * 
     */
    public Output<DatasetLabelSet> labelSet() {
        return this.labelSet;
    }
    /**
     * (Updatable) The labeling instructions for human labelers in rich text format
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="labelingInstructions", refs={String.class}, tree="[0]")
    private Output<String> labelingInstructions;

    /**
     * @return (Updatable) The labeling instructions for human labelers in rich text format
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> labelingInstructions() {
        return this.labelingInstructions;
    }
    /**
     * A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in FAILED or NEEDS_ATTENTION state.
     * 
     */
    @Export(name="lifecycleDetails", refs={String.class}, tree="[0]")
    private Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in FAILED or NEEDS_ATTENTION state.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * The sub-state of the dataset. IMPORT_DATASET - The dataset is being imported.
     * 
     */
    @Export(name="lifecycleSubstate", refs={String.class}, tree="[0]")
    private Output<String> lifecycleSubstate;

    /**
     * @return The sub-state of the dataset. IMPORT_DATASET - The dataset is being imported.
     * 
     */
    public Output<String> lifecycleSubstate() {
        return this.lifecycleSubstate;
    }
    /**
     * The state of a dataset. CREATING - The dataset is being created.  It will transition to ACTIVE when it is ready for labeling. ACTIVE   - The dataset is ready for labeling. UPDATING - The dataset is being updated.  It and its related resources may be unavailable for other updates until it returns to ACTIVE. NEEDS_ATTENTION - A dataset updation operation has failed due to validation or other errors and needs attention. DELETING - The dataset and its related resources are being deleted. DELETED  - The dataset has been deleted and is no longer available. FAILED   - The dataset has failed due to validation or other errors.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The state of a dataset. CREATING - The dataset is being created.  It will transition to ACTIVE when it is ready for labeling. ACTIVE   - The dataset is ready for labeling. UPDATING - The dataset is being updated.  It and its related resources may be unavailable for other updates until it returns to ACTIVE. NEEDS_ATTENTION - A dataset updation operation has failed due to validation or other errors and needs attention. DELETING - The dataset and its related resources are being deleted. DELETED  - The dataset has been deleted and is no longer available. FAILED   - The dataset has failed due to validation or other errors.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The date and time the resource was created, in the timestamp format defined by RFC3339.
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The date and time the resource was created, in the timestamp format defined by RFC3339.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The date and time the resource was last updated, in the timestamp format defined by RFC3339.
     * 
     */
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    /**
     * @return The date and time the resource was last updated, in the timestamp format defined by RFC3339.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public Dataset(String name) {
        this(name, DatasetArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public Dataset(String name, DatasetArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public Dataset(String name, DatasetArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DataLabellingService/dataset:Dataset", name, args == null ? DatasetArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private Dataset(String name, Output<String> id, @Nullable DatasetState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DataLabellingService/dataset:Dataset", name, state, makeResourceOptions(options, id));
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
    public static Dataset get(String name, Output<String> id, @Nullable DatasetState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new Dataset(name, id, state, options);
    }
}
