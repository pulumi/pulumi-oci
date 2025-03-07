// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.ApiGateway.ApiArgs;
import com.pulumi.oci.ApiGateway.inputs.ApiState;
import com.pulumi.oci.ApiGateway.outputs.ApiValidationResult;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Api resource in Oracle Cloud Infrastructure API Gateway service.
 * 
 * Creates a new API.
 * 
 * ## Example Usage
 * 
 * &lt;!--Start PulumiCodeChooser --&gt;
 * <pre>
 * {@code
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.ApiGateway.Api;
 * import com.pulumi.oci.ApiGateway.ApiArgs;
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
 *         var testApi = new Api("testApi", ApiArgs.builder()
 *             .compartmentId(compartmentId)
 *             .content(apiContent)
 *             .definedTags(Map.of("Operations.CostCenter", "42"))
 *             .displayName(apiDisplayName)
 *             .freeformTags(Map.of("Department", "Finance"))
 *             .build());
 * 
 *     }
 * }
 * }
 * </pre>
 * &lt;!--End PulumiCodeChooser --&gt;
 * 
 * ## Import
 * 
 * Apis can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:ApiGateway/api:Api test_api &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:ApiGateway/api:Api")
public class Api extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) API Specification content in json or yaml format
     * 
     */
    @Export(name="content", refs={String.class}, tree="[0]")
    private Output<String> content;

    /**
     * @return (Updatable) API Specification content in json or yaml format
     * 
     */
    public Output<String> content() {
        return this.content;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Export(name="definedTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Output<Map<String,String>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.  Example: `My new resource`
     * 
     */
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.  Example: `My new resource`
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="freeformTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<Map<String,String>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * A message describing the current lifecycleState in more detail. For ACTIVE state it describes if the document has been validated and the possible values are:
     * * &#39;New&#39; for just updated API Specifications
     * * &#39;Validating&#39; for a document which is being validated.
     * * &#39;Valid&#39; the document has been validated without any errors or warnings
     * * &#39;Warning&#39; the document has been validated and contains warnings
     * * &#39;Error&#39; the document has been validated and contains errors
     * * &#39;Failed&#39; the document validation failed
     * * &#39;Canceled&#39; the document validation was canceled
     * 
     */
    @Export(name="lifecycleDetails", refs={String.class}, tree="[0]")
    private Output<String> lifecycleDetails;

    /**
     * @return A message describing the current lifecycleState in more detail. For ACTIVE state it describes if the document has been validated and the possible values are:
     * * &#39;New&#39; for just updated API Specifications
     * * &#39;Validating&#39; for a document which is being validated.
     * * &#39;Valid&#39; the document has been validated without any errors or warnings
     * * &#39;Warning&#39; the document has been validated and contains warnings
     * * &#39;Error&#39; the document has been validated and contains errors
     * * &#39;Failed&#39; the document validation failed
     * * &#39;Canceled&#39; the document validation was canceled
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * Type of API Specification file.
     * 
     */
    @Export(name="specificationType", refs={String.class}, tree="[0]")
    private Output<String> specificationType;

    /**
     * @return Type of API Specification file.
     * 
     */
    public Output<String> specificationType() {
        return this.specificationType;
    }
    /**
     * The current state of the API.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current state of the API.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The time this resource was created. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The time this resource was created. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time this resource was last updated. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    /**
     * @return The time this resource was last updated. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * Status of each feature available from the API.
     * 
     */
    @Export(name="validationResults", refs={List.class,ApiValidationResult.class}, tree="[0,1]")
    private Output<List<ApiValidationResult>> validationResults;

    /**
     * @return Status of each feature available from the API.
     * 
     */
    public Output<List<ApiValidationResult>> validationResults() {
        return this.validationResults;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public Api(java.lang.String name) {
        this(name, ApiArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public Api(java.lang.String name, ApiArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public Api(java.lang.String name, ApiArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:ApiGateway/api:Api", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private Api(java.lang.String name, Output<java.lang.String> id, @Nullable ApiState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:ApiGateway/api:Api", name, state, makeResourceOptions(options, id), false);
    }

    private static ApiArgs makeArgs(ApiArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? ApiArgs.Empty : args;
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<java.lang.String> id) {
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
    public static Api get(java.lang.String name, Output<java.lang.String> id, @Nullable ApiState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new Api(name, id, state, options);
    }
}
