// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiLanguage;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.AiLanguage.EndpointArgs;
import com.pulumi.oci.AiLanguage.inputs.EndpointState;
import com.pulumi.oci.Utilities;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Endpoint resource in Oracle Cloud Infrastructure Ai Language service.
 * 
 * Creates a new endpoint and deploy the trained model
 * 
 * ## Example Usage
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.AiLanguage.Endpoint;
 * import com.pulumi.oci.AiLanguage.EndpointArgs;
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
 *         var testEndpoint = new Endpoint(&#34;testEndpoint&#34;, EndpointArgs.builder()        
 *             .compartmentId(var_.compartment_id())
 *             .modelId(oci_ai_language_model.test_model().id())
 *             .definedTags(Map.of(&#34;foo-namespace.bar-key&#34;, &#34;value&#34;))
 *             .description(var_.endpoint_description())
 *             .displayName(var_.endpoint_display_name())
 *             .freeformTags(Map.of(&#34;bar-key&#34;, &#34;value&#34;))
 *             .inferenceUnits(var_.endpoint_inference_units())
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * Endpoints can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:AiLanguage/endpoint:Endpoint test_endpoint &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:AiLanguage/endpoint:Endpoint")
public class Endpoint extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) compartment identifier for the endpoint
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) compartment identifier for the endpoint
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="definedTags", refs={Map.class,String.class,Object.class}, tree="[0,1,2]")
    private Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,Object>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) A short description of the an endpoint.
     * 
     */
    @Export(name="description", refs={String.class}, tree="[0]")
    private Output<String> description;

    /**
     * @return (Updatable) A short description of the an endpoint.
     * 
     */
    public Output<String> description() {
        return this.description;
    }
    /**
     * (Updatable) A user-friendly display name for the resource. It should be unique and can be modified. Avoid entering confidential information.
     * 
     */
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly display name for the resource. It should be unique and can be modified. Avoid entering confidential information.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="freeformTags", refs={Map.class,String.class,Object.class}, tree="[0,1,2]")
    private Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,Object>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * (Updatable) Number of replicas required for this endpoint. This will be optional parameter. Default will be 1.
     * 
     */
    @Export(name="inferenceUnits", refs={Integer.class}, tree="[0]")
    private Output<Integer> inferenceUnits;

    /**
     * @return (Updatable) Number of replicas required for this endpoint. This will be optional parameter. Default will be 1.
     * 
     */
    public Output<Integer> inferenceUnits() {
        return this.inferenceUnits;
    }
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in failed state.
     * 
     */
    @Export(name="lifecycleDetails", refs={String.class}, tree="[0]")
    private Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in failed state.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model to associate with the endpoint.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="modelId", refs={String.class}, tree="[0]")
    private Output<String> modelId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model to associate with the endpoint.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> modelId() {
        return this.modelId;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the Endpoint.
     * 
     */
    @Export(name="projectId", refs={String.class}, tree="[0]")
    private Output<String> projectId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the Endpoint.
     * 
     */
    public Output<String> projectId() {
        return this.projectId;
    }
    /**
     * The state of the endpoint.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The state of the endpoint.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Export(name="systemTags", refs={Map.class,String.class,Object.class}, tree="[0,1,2]")
    private Output<Map<String,Object>> systemTags;

    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Output<Map<String,Object>> systemTags() {
        return this.systemTags;
    }
    /**
     * The time the the endpoint was created. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The time the the endpoint was created. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time the endpoint was updated. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    /**
     * @return The time the endpoint was updated. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public Endpoint(String name) {
        this(name, EndpointArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public Endpoint(String name, EndpointArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public Endpoint(String name, EndpointArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:AiLanguage/endpoint:Endpoint", name, args == null ? EndpointArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private Endpoint(String name, Output<String> id, @Nullable EndpointState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:AiLanguage/endpoint:Endpoint", name, state, makeResourceOptions(options, id));
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
    public static Endpoint get(String name, Output<String> id, @Nullable EndpointState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new Endpoint(name, id, state, options);
    }
}