// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceMesh;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.ServiceMesh.VirtualDeploymentArgs;
import com.pulumi.oci.ServiceMesh.inputs.VirtualDeploymentState;
import com.pulumi.oci.ServiceMesh.outputs.VirtualDeploymentAccessLogging;
import com.pulumi.oci.ServiceMesh.outputs.VirtualDeploymentListener;
import com.pulumi.oci.ServiceMesh.outputs.VirtualDeploymentServiceDiscovery;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Virtual Deployment resource in Oracle Cloud Infrastructure Service Mesh service.
 * 
 * Creates a new VirtualDeployment.
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
 * import com.pulumi.oci.ServiceMesh.VirtualDeployment;
 * import com.pulumi.oci.ServiceMesh.VirtualDeploymentArgs;
 * import com.pulumi.oci.ServiceMesh.inputs.VirtualDeploymentAccessLoggingArgs;
 * import com.pulumi.oci.ServiceMesh.inputs.VirtualDeploymentListenerArgs;
 * import com.pulumi.oci.ServiceMesh.inputs.VirtualDeploymentServiceDiscoveryArgs;
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
 *         var testVirtualDeployment = new VirtualDeployment("testVirtualDeployment", VirtualDeploymentArgs.builder()
 *             .compartmentId(compartmentId)
 *             .name(virtualDeploymentName)
 *             .virtualServiceId(testVirtualService.id())
 *             .accessLogging(VirtualDeploymentAccessLoggingArgs.builder()
 *                 .isEnabled(virtualDeploymentAccessLoggingIsEnabled)
 *                 .build())
 *             .definedTags(Map.of("foo-namespace.bar-key", "value"))
 *             .description(virtualDeploymentDescription)
 *             .freeformTags(Map.of("bar-key", "value"))
 *             .listeners(VirtualDeploymentListenerArgs.builder()
 *                 .port(virtualDeploymentListenersPort)
 *                 .protocol(virtualDeploymentListenersProtocol)
 *                 .idleTimeoutInMs(virtualDeploymentListenersIdleTimeoutInMs)
 *                 .requestTimeoutInMs(virtualDeploymentListenersRequestTimeoutInMs)
 *                 .build())
 *             .serviceDiscovery(VirtualDeploymentServiceDiscoveryArgs.builder()
 *                 .type(virtualDeploymentServiceDiscoveryType)
 *                 .hostname(virtualDeploymentServiceDiscoveryHostname)
 *                 .build())
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
 * VirtualDeployments can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:ServiceMesh/virtualDeployment:VirtualDeployment test_virtual_deployment &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:ServiceMesh/virtualDeployment:VirtualDeployment")
public class VirtualDeployment extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) This configuration determines if logging is enabled and where the logs will be output.
     * 
     */
    @Export(name="accessLogging", refs={VirtualDeploymentAccessLogging.class}, tree="[0]")
    private Output<VirtualDeploymentAccessLogging> accessLogging;

    /**
     * @return (Updatable) This configuration determines if logging is enabled and where the logs will be output.
     * 
     */
    public Output<VirtualDeploymentAccessLogging> accessLogging() {
        return this.accessLogging;
    }
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
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
    @Export(name="definedTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,String>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
     * 
     */
    @Export(name="description", refs={String.class}, tree="[0]")
    private Output<String> description;

    /**
     * @return (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
     * 
     */
    public Output<String> description() {
        return this.description;
    }
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="freeformTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,String>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
     * 
     */
    @Export(name="lifecycleDetails", refs={String.class}, tree="[0]")
    private Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * (Updatable) The listeners for the virtual deployment.
     * 
     */
    @Export(name="listeners", refs={List.class,VirtualDeploymentListener.class}, tree="[0,1]")
    private Output<List<VirtualDeploymentListener>> listeners;

    /**
     * @return (Updatable) The listeners for the virtual deployment.
     * 
     */
    public Output<List<VirtualDeploymentListener>> listeners() {
        return this.listeners;
    }
    /**
     * A user-friendly name. The name must be unique within the same virtual service and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
     * 
     */
    @Export(name="name", refs={String.class}, tree="[0]")
    private Output<String> name;

    /**
     * @return A user-friendly name. The name must be unique within the same virtual service and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
     * 
     */
    public Output<String> name() {
        return this.name;
    }
    /**
     * (Updatable) Service Discovery configuration for virtual deployments.
     * 
     */
    @Export(name="serviceDiscovery", refs={VirtualDeploymentServiceDiscovery.class}, tree="[0]")
    private Output<VirtualDeploymentServiceDiscovery> serviceDiscovery;

    /**
     * @return (Updatable) Service Discovery configuration for virtual deployments.
     * 
     */
    public Output<VirtualDeploymentServiceDiscovery> serviceDiscovery() {
        return this.serviceDiscovery;
    }
    /**
     * The current state of the Resource.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current state of the Resource.
     * 
     */
    public Output<String> state() {
        return this.state;
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
     * The time when this resource was created in an RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The time when this resource was created in an RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time when this resource was updated in an RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    /**
     * @return The time when this resource was updated in an RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * The OCID of the service mesh in which this access policy is created.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="virtualServiceId", refs={String.class}, tree="[0]")
    private Output<String> virtualServiceId;

    /**
     * @return The OCID of the service mesh in which this access policy is created.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> virtualServiceId() {
        return this.virtualServiceId;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public VirtualDeployment(java.lang.String name) {
        this(name, VirtualDeploymentArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public VirtualDeployment(java.lang.String name, VirtualDeploymentArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public VirtualDeployment(java.lang.String name, VirtualDeploymentArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:ServiceMesh/virtualDeployment:VirtualDeployment", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private VirtualDeployment(java.lang.String name, Output<java.lang.String> id, @Nullable VirtualDeploymentState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:ServiceMesh/virtualDeployment:VirtualDeployment", name, state, makeResourceOptions(options, id), false);
    }

    private static VirtualDeploymentArgs makeArgs(VirtualDeploymentArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? VirtualDeploymentArgs.Empty : args;
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
    public static VirtualDeployment get(java.lang.String name, Output<java.lang.String> id, @Nullable VirtualDeploymentState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new VirtualDeployment(name, id, state, options);
    }
}
