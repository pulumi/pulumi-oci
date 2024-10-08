// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.StackMonitoring.DiscoveryJobArgs;
import com.pulumi.oci.StackMonitoring.inputs.DiscoveryJobState;
import com.pulumi.oci.StackMonitoring.outputs.DiscoveryJobDiscoveryDetails;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.String;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * This resource provides the Discovery Job resource in Oracle Cloud Infrastructure Stack Monitoring service.
 * 
 * API to create discovery Job and submit discovery Details to agent.
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
 * import com.pulumi.oci.StackMonitoring.DiscoveryJob;
 * import com.pulumi.oci.StackMonitoring.DiscoveryJobArgs;
 * import com.pulumi.oci.StackMonitoring.inputs.DiscoveryJobDiscoveryDetailsArgs;
 * import com.pulumi.oci.StackMonitoring.inputs.DiscoveryJobDiscoveryDetailsPropertiesArgs;
 * import com.pulumi.oci.StackMonitoring.inputs.DiscoveryJobDiscoveryDetailsCredentialsArgs;
 * import com.pulumi.oci.StackMonitoring.inputs.DiscoveryJobDiscoveryDetailsTagsArgs;
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
 *         var testDiscoveryJob = new DiscoveryJob("testDiscoveryJob", DiscoveryJobArgs.builder()
 *             .compartmentId(compartmentId)
 *             .discoveryDetails(DiscoveryJobDiscoveryDetailsArgs.builder()
 *                 .agentId(managementAgentId)
 *                 .properties(DiscoveryJobDiscoveryDetailsPropertiesArgs.builder()
 *                     .propertiesMap(discoveryJobDiscoveryDetailsPropertiesPropertiesMap)
 *                     .build())
 *                 .resourceName(discoveryJobDiscoveryDetailsResourceName)
 *                 .resourceType(discoveryJobDiscoveryDetailsResourceType)
 *                 .credentials(DiscoveryJobDiscoveryDetailsCredentialsArgs.builder()
 *                     .items(DiscoveryJobDiscoveryDetailsCredentialsItemArgs.builder()
 *                         .credentialName(discoveryJobDiscoveryDetailsCredentialsItemsCredentialName)
 *                         .credentialType(discoveryJobDiscoveryDetailsCredentialsItemsCredentialType)
 *                         .properties(DiscoveryJobDiscoveryDetailsCredentialsItemPropertiesArgs.builder()
 *                             .propertiesMap(discoveryJobDiscoveryDetailsCredentialsItemsPropertiesPropertiesMap)
 *                             .build())
 *                         .build())
 *                     .build())
 *                 .license(discoveryJobDiscoveryDetailsLicense)
 *                 .tags(DiscoveryJobDiscoveryDetailsTagsArgs.builder()
 *                     .propertiesMap(discoveryJobDiscoveryDetailsTagsPropertiesMap)
 *                     .build())
 *                 .build())
 *             .definedTags(Map.of("foo-namespace.bar-key", "value"))
 *             .discoveryClient(discoveryJobDiscoveryClient)
 *             .discoveryType(discoveryJobDiscoveryType)
 *             .freeformTags(Map.of("bar-key", "value"))
 *             .shouldPropagateTagsToDiscoveredResources(discoveryJobShouldPropagateTagsToDiscoveredResources)
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
 * DiscoveryJobs can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:StackMonitoring/discoveryJob:DiscoveryJob test_discovery_job &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:StackMonitoring/discoveryJob:DiscoveryJob")
public class DiscoveryJob extends com.pulumi.resources.CustomResource {
    /**
     * The OCID of Compartment
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return The OCID of Compartment
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="definedTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> definedTags;

    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,String>> definedTags() {
        return this.definedTags;
    }
    /**
     * Client who submits discovery job.
     * 
     */
    @Export(name="discoveryClient", refs={String.class}, tree="[0]")
    private Output<String> discoveryClient;

    /**
     * @return Client who submits discovery job.
     * 
     */
    public Output<String> discoveryClient() {
        return this.discoveryClient;
    }
    /**
     * The request of DiscoveryJob Resource details.
     * 
     */
    @Export(name="discoveryDetails", refs={DiscoveryJobDiscoveryDetails.class}, tree="[0]")
    private Output<DiscoveryJobDiscoveryDetails> discoveryDetails;

    /**
     * @return The request of DiscoveryJob Resource details.
     * 
     */
    public Output<DiscoveryJobDiscoveryDetails> discoveryDetails() {
        return this.discoveryDetails;
    }
    /**
     * Add option submits new discovery Job. Add with retry option to re-submit failed discovery job. Refresh option refreshes the existing discovered resources.
     * 
     */
    @Export(name="discoveryType", refs={String.class}, tree="[0]")
    private Output</* @Nullable */ String> discoveryType;

    /**
     * @return Add option submits new discovery Job. Add with retry option to re-submit failed discovery job. Refresh option refreshes the existing discovered resources.
     * 
     */
    public Output<Optional<String>> discoveryType() {
        return Codegen.optional(this.discoveryType);
    }
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="freeformTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> freeformTags;

    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,String>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * If this parameter set to true, the specified tags will be applied  to all resources discovered in the current request.  Default is true.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="shouldPropagateTagsToDiscoveredResources", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> shouldPropagateTagsToDiscoveredResources;

    /**
     * @return If this parameter set to true, the specified tags will be applied  to all resources discovered in the current request.  Default is true.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<Boolean> shouldPropagateTagsToDiscoveredResources() {
        return this.shouldPropagateTagsToDiscoveredResources;
    }
    /**
     * The current state of the DiscoveryJob Resource.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current state of the DiscoveryJob Resource.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * Specifies the status of the discovery job
     * 
     */
    @Export(name="status", refs={String.class}, tree="[0]")
    private Output<String> status;

    /**
     * @return Specifies the status of the discovery job
     * 
     */
    public Output<String> status() {
        return this.status;
    }
    /**
     * The short summary of the status of the discovery job
     * 
     */
    @Export(name="statusMessage", refs={String.class}, tree="[0]")
    private Output<String> statusMessage;

    /**
     * @return The short summary of the status of the discovery job
     * 
     */
    public Output<String> statusMessage() {
        return this.statusMessage;
    }
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Export(name="systemTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> systemTags;

    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Output<Map<String,String>> systemTags() {
        return this.systemTags;
    }
    /**
     * The OCID of Tenant
     * 
     */
    @Export(name="tenantId", refs={String.class}, tree="[0]")
    private Output<String> tenantId;

    /**
     * @return The OCID of Tenant
     * 
     */
    public Output<String> tenantId() {
        return this.tenantId;
    }
    /**
     * The time the discovery Job was updated.
     * 
     */
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    /**
     * @return The time the discovery Job was updated.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * The OCID of user in which the job is submitted
     * 
     */
    @Export(name="userId", refs={String.class}, tree="[0]")
    private Output<String> userId;

    /**
     * @return The OCID of user in which the job is submitted
     * 
     */
    public Output<String> userId() {
        return this.userId;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public DiscoveryJob(java.lang.String name) {
        this(name, DiscoveryJobArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public DiscoveryJob(java.lang.String name, DiscoveryJobArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public DiscoveryJob(java.lang.String name, DiscoveryJobArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:StackMonitoring/discoveryJob:DiscoveryJob", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private DiscoveryJob(java.lang.String name, Output<java.lang.String> id, @Nullable DiscoveryJobState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:StackMonitoring/discoveryJob:DiscoveryJob", name, state, makeResourceOptions(options, id), false);
    }

    private static DiscoveryJobArgs makeArgs(DiscoveryJobArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? DiscoveryJobArgs.Empty : args;
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
    public static DiscoveryJob get(java.lang.String name, Output<java.lang.String> id, @Nullable DiscoveryJobState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new DiscoveryJob(name, id, state, options);
    }
}
