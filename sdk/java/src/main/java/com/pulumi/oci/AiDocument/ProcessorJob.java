// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiDocument;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.AiDocument.ProcessorJobArgs;
import com.pulumi.oci.AiDocument.inputs.ProcessorJobState;
import com.pulumi.oci.AiDocument.outputs.ProcessorJobInputLocation;
import com.pulumi.oci.AiDocument.outputs.ProcessorJobOutputLocation;
import com.pulumi.oci.AiDocument.outputs.ProcessorJobProcessorConfig;
import com.pulumi.oci.Utilities;
import java.lang.Double;
import java.lang.String;
import javax.annotation.Nullable;

/**
 * This resource provides the Processor Job resource in Oracle Cloud Infrastructure Ai Document service.
 * 
 * Create a processor job for document analysis.
 * 
 * ## Example Usage
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.AiDocument.ProcessorJob;
 * import com.pulumi.oci.AiDocument.ProcessorJobArgs;
 * import com.pulumi.oci.AiDocument.inputs.ProcessorJobInputLocationArgs;
 * import com.pulumi.oci.AiDocument.inputs.ProcessorJobOutputLocationArgs;
 * import com.pulumi.oci.AiDocument.inputs.ProcessorJobProcessorConfigArgs;
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
 *         var testProcessorJob = new ProcessorJob(&#34;testProcessorJob&#34;, ProcessorJobArgs.builder()        
 *             .compartmentId(var_.compartment_id())
 *             .inputLocation(ProcessorJobInputLocationArgs.builder()
 *                 .sourceType(var_.processor_job_input_location_source_type())
 *                 .data(var_.processor_job_input_location_data())
 *                 .objectLocations(ProcessorJobInputLocationObjectLocationArgs.builder()
 *                     .bucket(var_.processor_job_input_location_object_locations_bucket())
 *                     .namespace(var_.processor_job_input_location_object_locations_namespace())
 *                     .object(var_.processor_job_input_location_object_locations_object())
 *                     .build())
 *                 .build())
 *             .outputLocation(ProcessorJobOutputLocationArgs.builder()
 *                 .bucket(var_.processor_job_output_location_bucket())
 *                 .namespace(var_.processor_job_output_location_namespace())
 *                 .prefix(var_.processor_job_output_location_prefix())
 *                 .build())
 *             .processorConfig(ProcessorJobProcessorConfigArgs.builder()
 *                 .features(ProcessorJobProcessorConfigFeatureArgs.builder()
 *                     .featureType(var_.processor_job_processor_config_features_feature_type())
 *                     .generateSearchablePdf(var_.processor_job_processor_config_features_generate_searchable_pdf())
 *                     .maxResults(var_.processor_job_processor_config_features_max_results())
 *                     .modelId(oci_ai_document_model.test_model().id())
 *                     .build())
 *                 .processorType(var_.processor_job_processor_config_processor_type())
 *                 .documentType(var_.processor_job_processor_config_document_type())
 *                 .isZipOutputEnabled(var_.processor_job_processor_config_is_zip_output_enabled())
 *                 .language(var_.processor_job_processor_config_language())
 *                 .build())
 *             .displayName(var_.processor_job_display_name())
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * ProcessorJobs can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:AiDocument/processorJob:ProcessorJob test_processor_job &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:AiDocument/processorJob:ProcessorJob")
public class ProcessorJob extends com.pulumi.resources.CustomResource {
    /**
     * The compartment identifier.
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return The compartment identifier.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * The display name of the processor job.
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return The display name of the processor job.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * The location of the inputs.
     * 
     */
    @Export(name="inputLocation", type=ProcessorJobInputLocation.class, parameters={})
    private Output<ProcessorJobInputLocation> inputLocation;

    /**
     * @return The location of the inputs.
     * 
     */
    public Output<ProcessorJobInputLocation> inputLocation() {
        return this.inputLocation;
    }
    /**
     * The detailed status of FAILED state.
     * 
     */
    @Export(name="lifecycleDetails", type=String.class, parameters={})
    private Output<String> lifecycleDetails;

    /**
     * @return The detailed status of FAILED state.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * The Object Storage Location.
     * 
     */
    @Export(name="outputLocation", type=ProcessorJobOutputLocation.class, parameters={})
    private Output<ProcessorJobOutputLocation> outputLocation;

    /**
     * @return The Object Storage Location.
     * 
     */
    public Output<ProcessorJobOutputLocation> outputLocation() {
        return this.outputLocation;
    }
    /**
     * How much progress the operation has made, compared to the total amount of work to be performed.
     * 
     */
    @Export(name="percentComplete", type=Double.class, parameters={})
    private Output<Double> percentComplete;

    /**
     * @return How much progress the operation has made, compared to the total amount of work to be performed.
     * 
     */
    public Output<Double> percentComplete() {
        return this.percentComplete;
    }
    /**
     * The configuration of a processor.
     * 
     */
    @Export(name="processorConfig", type=ProcessorJobProcessorConfig.class, parameters={})
    private Output<ProcessorJobProcessorConfig> processorConfig;

    /**
     * @return The configuration of a processor.
     * 
     */
    public Output<ProcessorJobProcessorConfig> processorConfig() {
        return this.processorConfig;
    }
    /**
     * The current state of the processor job.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current state of the processor job.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The job acceptance time.
     * 
     */
    @Export(name="timeAccepted", type=String.class, parameters={})
    private Output<String> timeAccepted;

    /**
     * @return The job acceptance time.
     * 
     */
    public Output<String> timeAccepted() {
        return this.timeAccepted;
    }
    /**
     * The job finish time.
     * 
     */
    @Export(name="timeFinished", type=String.class, parameters={})
    private Output<String> timeFinished;

    /**
     * @return The job finish time.
     * 
     */
    public Output<String> timeFinished() {
        return this.timeFinished;
    }
    /**
     * The job start time.
     * 
     */
    @Export(name="timeStarted", type=String.class, parameters={})
    private Output<String> timeStarted;

    /**
     * @return The job start time.
     * 
     */
    public Output<String> timeStarted() {
        return this.timeStarted;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public ProcessorJob(String name) {
        this(name, ProcessorJobArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public ProcessorJob(String name, ProcessorJobArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public ProcessorJob(String name, ProcessorJobArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:AiDocument/processorJob:ProcessorJob", name, args == null ? ProcessorJobArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private ProcessorJob(String name, Output<String> id, @Nullable ProcessorJobState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:AiDocument/processorJob:ProcessorJob", name, state, makeResourceOptions(options, id));
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
    public static ProcessorJob get(String name, Output<String> id, @Nullable ProcessorJobState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new ProcessorJob(name, id, state, options);
    }
}