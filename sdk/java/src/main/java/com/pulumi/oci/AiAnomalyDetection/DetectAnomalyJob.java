// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiAnomalyDetection;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.AiAnomalyDetection.DetectAnomalyJobArgs;
import com.pulumi.oci.AiAnomalyDetection.inputs.DetectAnomalyJobState;
import com.pulumi.oci.AiAnomalyDetection.outputs.DetectAnomalyJobInputDetails;
import com.pulumi.oci.AiAnomalyDetection.outputs.DetectAnomalyJobOutputDetails;
import com.pulumi.oci.Utilities;
import java.lang.Double;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Detect Anomaly Job resource in Oracle Cloud Infrastructure Ai Anomaly Detection service.
 * 
 * Creates a job to perform anomaly detection.
 * 
 * ## Example Usage
 * 
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.AiAnomalyDetection.DetectAnomalyJob;
 * import com.pulumi.oci.AiAnomalyDetection.DetectAnomalyJobArgs;
 * import com.pulumi.oci.AiAnomalyDetection.inputs.DetectAnomalyJobInputDetailsArgs;
 * import com.pulumi.oci.AiAnomalyDetection.inputs.DetectAnomalyJobOutputDetailsArgs;
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
 *         var testDetectAnomalyJob = new DetectAnomalyJob(&#34;testDetectAnomalyJob&#34;, DetectAnomalyJobArgs.builder()        
 *             .compartmentId(var_.compartment_id())
 *             .inputDetails(DetectAnomalyJobInputDetailsArgs.builder()
 *                 .inputType(var_.detect_anomaly_job_input_details_input_type())
 *                 .content(var_.detect_anomaly_job_input_details_content())
 *                 .contentType(var_.detect_anomaly_job_input_details_content_type())
 *                 .datas(DetectAnomalyJobInputDetailsDataArgs.builder()
 *                     .timestamp(var_.detect_anomaly_job_input_details_data_timestamp())
 *                     .values(var_.detect_anomaly_job_input_details_data_values())
 *                     .build())
 *                 .objectLocations(DetectAnomalyJobInputDetailsObjectLocationArgs.builder()
 *                     .bucket(var_.detect_anomaly_job_input_details_object_locations_bucket())
 *                     .namespace(var_.detect_anomaly_job_input_details_object_locations_namespace())
 *                     .object(var_.detect_anomaly_job_input_details_object_locations_object())
 *                     .build())
 *                 .signalNames(var_.detect_anomaly_job_input_details_signal_names())
 *                 .build())
 *             .modelId(oci_ai_anomaly_detection_model.test_model().id())
 *             .outputDetails(DetectAnomalyJobOutputDetailsArgs.builder()
 *                 .bucket(var_.detect_anomaly_job_output_details_bucket())
 *                 .namespace(var_.detect_anomaly_job_output_details_namespace())
 *                 .outputType(var_.detect_anomaly_job_output_details_output_type())
 *                 .prefix(var_.detect_anomaly_job_output_details_prefix())
 *                 .build())
 *             .areAllEstimatesRequired(var_.detect_anomaly_job_are_all_estimates_required())
 *             .description(var_.detect_anomaly_job_description())
 *             .displayName(var_.detect_anomaly_job_display_name())
 *             .sensitivity(var_.detect_anomaly_job_sensitivity())
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * DetectAnomalyJobs can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:AiAnomalyDetection/detectAnomalyJob:DetectAnomalyJob test_detect_anomaly_job &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:AiAnomalyDetection/detectAnomalyJob:DetectAnomalyJob")
public class DetectAnomalyJob extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) The OCID of the compartment that starts the job.
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the compartment that starts the job.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="definedTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> definedTags;

    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,Object>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) A short description of the detect anomaly job.
     * 
     */
    @Export(name="description", type=String.class, parameters={})
    private Output<String> description;

    /**
     * @return (Updatable) A short description of the detect anomaly job.
     * 
     */
    public Output<String> description() {
        return this.description;
    }
    /**
     * (Updatable) Detect anomaly job display name.
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return (Updatable) Detect anomaly job display name.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="freeformTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> freeformTags;

    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,Object>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * Detect anomaly asynchronous job details.
     * 
     */
    @Export(name="inputDetails", type=DetectAnomalyJobInputDetails.class, parameters={})
    private Output<DetectAnomalyJobInputDetails> inputDetails;

    /**
     * @return Detect anomaly asynchronous job details.
     * 
     */
    public Output<DetectAnomalyJobInputDetails> inputDetails() {
        return this.inputDetails;
    }
    /**
     * The current state details of the batch document job.
     * 
     */
    @Export(name="lifecycleStateDetails", type=String.class, parameters={})
    private Output<String> lifecycleStateDetails;

    /**
     * @return The current state details of the batch document job.
     * 
     */
    public Output<String> lifecycleStateDetails() {
        return this.lifecycleStateDetails;
    }
    /**
     * The OCID of the trained model.
     * 
     */
    @Export(name="modelId", type=String.class, parameters={})
    private Output<String> modelId;

    /**
     * @return The OCID of the trained model.
     * 
     */
    public Output<String> modelId() {
        return this.modelId;
    }
    /**
     * Detect anomaly job output details.
     * 
     */
    @Export(name="outputDetails", type=DetectAnomalyJobOutputDetails.class, parameters={})
    private Output<DetectAnomalyJobOutputDetails> outputDetails;

    /**
     * @return Detect anomaly job output details.
     * 
     */
    public Output<DetectAnomalyJobOutputDetails> outputDetails() {
        return this.outputDetails;
    }
    /**
     * The OCID of the project.
     * 
     */
    @Export(name="projectId", type=String.class, parameters={})
    private Output<String> projectId;

    /**
     * @return The OCID of the project.
     * 
     */
    public Output<String> projectId() {
        return this.projectId;
    }
    /**
     * The value that customer can adjust to control the sensitivity of anomaly detection
     * 
     */
    @Export(name="sensitivity", type=Double.class, parameters={})
    private Output<Double> sensitivity;

    /**
     * @return The value that customer can adjust to control the sensitivity of anomaly detection
     * 
     */
    public Output<Double> sensitivity() {
        return this.sensitivity;
    }
    /**
     * The current state of the batch document job.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current state of the batch document job.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Export(name="systemTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> systemTags;

    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Output<Map<String,Object>> systemTags() {
        return this.systemTags;
    }
    /**
     * Job accepted time
     * 
     */
    @Export(name="timeAccepted", type=String.class, parameters={})
    private Output<String> timeAccepted;

    /**
     * @return Job accepted time
     * 
     */
    public Output<String> timeAccepted() {
        return this.timeAccepted;
    }
    /**
     * Job finished time
     * 
     */
    @Export(name="timeFinished", type=String.class, parameters={})
    private Output<String> timeFinished;

    /**
     * @return Job finished time
     * 
     */
    public Output<String> timeFinished() {
        return this.timeFinished;
    }
    /**
     * Job started time
     * 
     */
    @Export(name="timeStarted", type=String.class, parameters={})
    private Output<String> timeStarted;

    /**
     * @return Job started time
     * 
     */
    public Output<String> timeStarted() {
        return this.timeStarted;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public DetectAnomalyJob(String name) {
        this(name, DetectAnomalyJobArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public DetectAnomalyJob(String name, DetectAnomalyJobArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public DetectAnomalyJob(String name, DetectAnomalyJobArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:AiAnomalyDetection/detectAnomalyJob:DetectAnomalyJob", name, args == null ? DetectAnomalyJobArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private DetectAnomalyJob(String name, Output<String> id, @Nullable DetectAnomalyJobState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:AiAnomalyDetection/detectAnomalyJob:DetectAnomalyJob", name, state, makeResourceOptions(options, id));
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
    public static DetectAnomalyJob get(String name, Output<String> id, @Nullable DetectAnomalyJobState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new DetectAnomalyJob(name, id, state, options);
    }
}