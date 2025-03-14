// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkLoadBalancer;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.NetworkLoadBalancer.BackendArgs;
import com.pulumi.oci.NetworkLoadBalancer.inputs.BackendState;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import javax.annotation.Nullable;

/**
 * This resource provides the Backend resource in Oracle Cloud Infrastructure Network Load Balancer service.
 * 
 * Adds a backend server to a backend set.
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
 * import com.pulumi.oci.NetworkLoadBalancer.Backend;
 * import com.pulumi.oci.NetworkLoadBalancer.BackendArgs;
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
 *         var testBackend = new Backend("testBackend", BackendArgs.builder()
 *             .backendSetName(testBackendSet.name())
 *             .networkLoadBalancerId(testNetworkLoadBalancer.id())
 *             .port(backendPort)
 *             .ipAddress(backendIpAddress)
 *             .isBackup(backendIsBackup)
 *             .isDrain(backendIsDrain)
 *             .isOffline(backendIsOffline)
 *             .name(backendName)
 *             .targetId(testTarget.id())
 *             .weight(backendWeight)
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
 * Backends can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:NetworkLoadBalancer/backend:Backend test_backend &#34;networkLoadBalancers/{networkLoadBalancerId}/backendSets/{backendSetName}/backends/{backendName}&#34;
 * ```
 * 
 */
@ResourceType(type="oci:NetworkLoadBalancer/backend:Backend")
public class Backend extends com.pulumi.resources.CustomResource {
    /**
     * The name of the backend set to which to add the backend server.  Example: `example_backend_set`
     * 
     */
    @Export(name="backendSetName", refs={String.class}, tree="[0]")
    private Output<String> backendSetName;

    /**
     * @return The name of the backend set to which to add the backend server.  Example: `example_backend_set`
     * 
     */
    public Output<String> backendSetName() {
        return this.backendSetName;
    }
    /**
     * The IP address of the backend server. Example: `10.0.0.3`
     * 
     */
    @Export(name="ipAddress", refs={String.class}, tree="[0]")
    private Output<String> ipAddress;

    /**
     * @return The IP address of the backend server. Example: `10.0.0.3`
     * 
     */
    public Output<String> ipAddress() {
        return this.ipAddress;
    }
    /**
     * (Updatable) Whether the network load balancer should treat this server as a backup unit. If `true`, then the network load balancer forwards no ingress traffic to this backend server unless all other backend servers not marked as &#34;isBackup&#34; fail the health check policy.  Example: `false`
     * 
     */
    @Export(name="isBackup", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> isBackup;

    /**
     * @return (Updatable) Whether the network load balancer should treat this server as a backup unit. If `true`, then the network load balancer forwards no ingress traffic to this backend server unless all other backend servers not marked as &#34;isBackup&#34; fail the health check policy.  Example: `false`
     * 
     */
    public Output<Boolean> isBackup() {
        return this.isBackup;
    }
    /**
     * (Updatable) Whether the network load balancer should drain this server. Servers marked &#34;isDrain&#34; receive no incoming traffic.  Example: `false`
     * 
     */
    @Export(name="isDrain", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> isDrain;

    /**
     * @return (Updatable) Whether the network load balancer should drain this server. Servers marked &#34;isDrain&#34; receive no incoming traffic.  Example: `false`
     * 
     */
    public Output<Boolean> isDrain() {
        return this.isDrain;
    }
    /**
     * (Updatable) Whether the network load balancer should treat this server as offline. Offline servers receive no incoming traffic.  Example: `false`
     * 
     */
    @Export(name="isOffline", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> isOffline;

    /**
     * @return (Updatable) Whether the network load balancer should treat this server as offline. Offline servers receive no incoming traffic.  Example: `false`
     * 
     */
    public Output<Boolean> isOffline() {
        return this.isOffline;
    }
    /**
     * Optional unique name identifying the backend within the backend set. If not specified, then one will be generated. Example: `webServer1`
     * 
     */
    @Export(name="name", refs={String.class}, tree="[0]")
    private Output<String> name;

    /**
     * @return Optional unique name identifying the backend within the backend set. If not specified, then one will be generated. Example: `webServer1`
     * 
     */
    public Output<String> name() {
        return this.name;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
     * 
     */
    @Export(name="networkLoadBalancerId", refs={String.class}, tree="[0]")
    private Output<String> networkLoadBalancerId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
     * 
     */
    public Output<String> networkLoadBalancerId() {
        return this.networkLoadBalancerId;
    }
    /**
     * The communication port for the backend server.  Example: `8080`
     * 
     */
    @Export(name="port", refs={Integer.class}, tree="[0]")
    private Output<Integer> port;

    /**
     * @return The communication port for the backend server.  Example: `8080`
     * 
     */
    public Output<Integer> port() {
        return this.port;
    }
    /**
     * The IP OCID/Instance OCID associated with the backend server. Example: `ocid1.privateip..oc1.&lt;var&gt;&amp;lt;unique_ID&amp;gt;&lt;/var&gt;`
     * 
     */
    @Export(name="targetId", refs={String.class}, tree="[0]")
    private Output<String> targetId;

    /**
     * @return The IP OCID/Instance OCID associated with the backend server. Example: `ocid1.privateip..oc1.&lt;var&gt;&amp;lt;unique_ID&amp;gt;&lt;/var&gt;`
     * 
     */
    public Output<String> targetId() {
        return this.targetId;
    }
    /**
     * (Updatable) The network load balancing policy weight assigned to the server. Backend servers with a higher weight receive a larger proportion of incoming traffic. For example, a server weighted &#39;3&#39; receives three times the number of new connections as a server weighted &#39;1&#39;. For more information about network load balancer policies, see [Network Load Balancer Policies](https://docs.cloud.oracle.com/iaas/Content/NetworkLoadBalancer/introduction.htm#Policies).  Example: `3`
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="weight", refs={Integer.class}, tree="[0]")
    private Output<Integer> weight;

    /**
     * @return (Updatable) The network load balancing policy weight assigned to the server. Backend servers with a higher weight receive a larger proportion of incoming traffic. For example, a server weighted &#39;3&#39; receives three times the number of new connections as a server weighted &#39;1&#39;. For more information about network load balancer policies, see [Network Load Balancer Policies](https://docs.cloud.oracle.com/iaas/Content/NetworkLoadBalancer/introduction.htm#Policies).  Example: `3`
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<Integer> weight() {
        return this.weight;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public Backend(java.lang.String name) {
        this(name, BackendArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public Backend(java.lang.String name, BackendArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public Backend(java.lang.String name, BackendArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:NetworkLoadBalancer/backend:Backend", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private Backend(java.lang.String name, Output<java.lang.String> id, @Nullable BackendState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:NetworkLoadBalancer/backend:Backend", name, state, makeResourceOptions(options, id), false);
    }

    private static BackendArgs makeArgs(BackendArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? BackendArgs.Empty : args;
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
    public static Backend get(java.lang.String name, Output<java.lang.String> id, @Nullable BackendState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new Backend(name, id, state, options);
    }
}
