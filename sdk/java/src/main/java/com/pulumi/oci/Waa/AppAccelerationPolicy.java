// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waa;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Utilities;
import com.pulumi.oci.Waa.AppAccelerationPolicyArgs;
import com.pulumi.oci.Waa.inputs.AppAccelerationPolicyState;
import com.pulumi.oci.Waa.outputs.AppAccelerationPolicyResponseCachingPolicy;
import com.pulumi.oci.Waa.outputs.AppAccelerationPolicyResponseCompressionPolicy;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Web App Acceleration Policy resource in Oracle Cloud Infrastructure Waa service.
 * 
 * Creates a new WebAppAccelerationPolicy.
 * 
 * ## Example Usage
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.Waa.AppAccelerationPolicy;
 * import com.pulumi.oci.Waa.AppAccelerationPolicyArgs;
 * import com.pulumi.oci.Waa.inputs.AppAccelerationPolicyResponseCachingPolicyArgs;
 * import com.pulumi.oci.Waa.inputs.AppAccelerationPolicyResponseCompressionPolicyArgs;
 * import com.pulumi.oci.Waa.inputs.AppAccelerationPolicyResponseCompressionPolicyGzipCompressionArgs;
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
 *         var testWebAppAccelerationPolicy = new AppAccelerationPolicy(&#34;testWebAppAccelerationPolicy&#34;, AppAccelerationPolicyArgs.builder()        
 *             .compartmentId(var_.compartment_id())
 *             .definedTags(Map.of(&#34;foo-namespace.bar-key&#34;, &#34;value&#34;))
 *             .displayName(var_.web_app_acceleration_policy_display_name())
 *             .freeformTags(Map.of(&#34;bar-key&#34;, &#34;value&#34;))
 *             .responseCachingPolicy(AppAccelerationPolicyResponseCachingPolicyArgs.builder()
 *                 .isResponseHeaderBasedCachingEnabled(var_.web_app_acceleration_policy_response_caching_policy_is_response_header_based_caching_enabled())
 *                 .build())
 *             .responseCompressionPolicy(AppAccelerationPolicyResponseCompressionPolicyArgs.builder()
 *                 .gzipCompression(AppAccelerationPolicyResponseCompressionPolicyGzipCompressionArgs.builder()
 *                     .isEnabled(var_.web_app_acceleration_policy_response_compression_policy_gzip_compression_is_enabled())
 *                     .build())
 *                 .build())
 *             .systemTags(var_.web_app_acceleration_policy_system_tags())
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * WebAppAccelerationPolicies can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:Waa/appAccelerationPolicy:AppAccelerationPolicy test_web_app_acceleration_policy &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Waa/appAccelerationPolicy:AppAccelerationPolicy")
public class AppAccelerationPolicy extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="definedTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,Object>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) WebAppAccelerationPolicy display name, can be renamed.
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return (Updatable) WebAppAccelerationPolicy display name, can be renamed.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="freeformTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,Object>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in FAILED state.
     * 
     */
    @Export(name="lifecycleDetails", type=String.class, parameters={})
    private Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in FAILED state.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * (Updatable) An object that specifies an HTTP response caching policy.
     * 
     */
    @Export(name="responseCachingPolicy", type=AppAccelerationPolicyResponseCachingPolicy.class, parameters={})
    private Output<AppAccelerationPolicyResponseCachingPolicy> responseCachingPolicy;

    /**
     * @return (Updatable) An object that specifies an HTTP response caching policy.
     * 
     */
    public Output<AppAccelerationPolicyResponseCachingPolicy> responseCachingPolicy() {
        return this.responseCachingPolicy;
    }
    /**
     * (Updatable) An object that specifies a compression policy for HTTP response from ENABLEMENT POINT to the client.
     * 
     */
    @Export(name="responseCompressionPolicy", type=AppAccelerationPolicyResponseCompressionPolicy.class, parameters={})
    private Output<AppAccelerationPolicyResponseCompressionPolicy> responseCompressionPolicy;

    /**
     * @return (Updatable) An object that specifies a compression policy for HTTP response from ENABLEMENT POINT to the client.
     * 
     */
    public Output<AppAccelerationPolicyResponseCompressionPolicy> responseCompressionPolicy() {
        return this.responseCompressionPolicy;
    }
    /**
     * The current state of the WebAppAccelerationPolicy.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current state of the WebAppAccelerationPolicy.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * (Updatable) Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Export(name="systemTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> systemTags;

    /**
     * @return (Updatable) Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Output<Map<String,Object>> systemTags() {
        return this.systemTags;
    }
    /**
     * The time the WebAppAccelerationPolicy was created. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The time the WebAppAccelerationPolicy was created. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time the WebAppAccelerationPolicy was updated. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeUpdated", type=String.class, parameters={})
    private Output<String> timeUpdated;

    /**
     * @return The time the WebAppAccelerationPolicy was updated. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public AppAccelerationPolicy(String name) {
        this(name, AppAccelerationPolicyArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public AppAccelerationPolicy(String name, AppAccelerationPolicyArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public AppAccelerationPolicy(String name, AppAccelerationPolicyArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Waa/appAccelerationPolicy:AppAccelerationPolicy", name, args == null ? AppAccelerationPolicyArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private AppAccelerationPolicy(String name, Output<String> id, @Nullable AppAccelerationPolicyState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Waa/appAccelerationPolicy:AppAccelerationPolicy", name, state, makeResourceOptions(options, id));
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
    public static AppAccelerationPolicy get(String name, Output<String> id, @Nullable AppAccelerationPolicyState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new AppAccelerationPolicy(name, id, state, options);
    }
}