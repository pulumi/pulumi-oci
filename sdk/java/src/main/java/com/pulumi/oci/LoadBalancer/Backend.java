// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.LoadBalancer.BackendArgs;
import com.pulumi.oci.LoadBalancer.inputs.BackendState;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * This resource provides the Backend resource in Oracle Cloud Infrastructure Load Balancer service.
 * 
 * Adds a backend server to a backend set.
 * 
 * ## Example Usage
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.LoadBalancer.Backend;
 * import com.pulumi.oci.LoadBalancer.BackendArgs;
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
 *         var testBackend = new Backend(&#34;testBackend&#34;, BackendArgs.builder()        
 *             .backendsetName(oci_load_balancer_backend_set.test_backend_set().name())
 *             .ipAddress(var_.backend_ip_address())
 *             .loadBalancerId(oci_load_balancer_load_balancer.test_load_balancer().id())
 *             .port(var_.backend_port())
 *             .backup(var_.backend_backup())
 *             .drain(var_.backend_drain())
 *             .offline(var_.backend_offline())
 *             .weight(var_.backend_weight())
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * Backends can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:LoadBalancer/backend:Backend test_backend &#34;loadBalancers/{loadBalancerId}/backendSets/{backendSetName}/backends/{backendName}&#34;
 * ```
 * 
 */
@ResourceType(type="oci:LoadBalancer/backend:Backend")
public class Backend extends com.pulumi.resources.CustomResource {
    /**
     * The name of the backend set to add the backend server to.  Example: `example_backend_set`
     * 
     */
    @Export(name="backendsetName", type=String.class, parameters={})
    private Output<String> backendsetName;

    /**
     * @return The name of the backend set to add the backend server to.  Example: `example_backend_set`
     * 
     */
    public Output<String> backendsetName() {
        return this.backendsetName;
    }
    /**
     * (Updatable) Whether the load balancer should treat this server as a backup unit. If `true`, the load balancer forwards no ingress traffic to this backend server unless all other backend servers not marked as &#34;backup&#34; fail the health check policy.
     * 
     */
    @Export(name="backup", type=Boolean.class, parameters={})
    private Output</* @Nullable */ Boolean> backup;

    /**
     * @return (Updatable) Whether the load balancer should treat this server as a backup unit. If `true`, the load balancer forwards no ingress traffic to this backend server unless all other backend servers not marked as &#34;backup&#34; fail the health check policy.
     * 
     */
    public Output<Optional<Boolean>> backup() {
        return Codegen.optional(this.backup);
    }
    /**
     * (Updatable) Whether the load balancer should drain this server. Servers marked &#34;drain&#34; receive no new incoming traffic.  Example: `false`
     * 
     */
    @Export(name="drain", type=Boolean.class, parameters={})
    private Output<Boolean> drain;

    /**
     * @return (Updatable) Whether the load balancer should drain this server. Servers marked &#34;drain&#34; receive no new incoming traffic.  Example: `false`
     * 
     */
    public Output<Boolean> drain() {
        return this.drain;
    }
    /**
     * The IP address of the backend server.  Example: `10.0.0.3`
     * 
     */
    @Export(name="ipAddress", type=String.class, parameters={})
    private Output<String> ipAddress;

    /**
     * @return The IP address of the backend server.  Example: `10.0.0.3`
     * 
     */
    public Output<String> ipAddress() {
        return this.ipAddress;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the backend set and servers.
     * 
     */
    @Export(name="loadBalancerId", type=String.class, parameters={})
    private Output<String> loadBalancerId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the backend set and servers.
     * 
     */
    public Output<String> loadBalancerId() {
        return this.loadBalancerId;
    }
    /**
     * A read-only field showing the IP address and port that uniquely identify this backend server in the backend set.  Example: `10.0.0.3:8080`
     * 
     */
    @Export(name="name", type=String.class, parameters={})
    private Output<String> name;

    /**
     * @return A read-only field showing the IP address and port that uniquely identify this backend server in the backend set.  Example: `10.0.0.3:8080`
     * 
     */
    public Output<String> name() {
        return this.name;
    }
    /**
     * (Updatable) Whether the load balancer should treat this server as offline. Offline servers receive no incoming traffic.  Example: `false`
     * 
     */
    @Export(name="offline", type=Boolean.class, parameters={})
    private Output<Boolean> offline;

    /**
     * @return (Updatable) Whether the load balancer should treat this server as offline. Offline servers receive no incoming traffic.  Example: `false`
     * 
     */
    public Output<Boolean> offline() {
        return this.offline;
    }
    /**
     * The communication port for the backend server.  Example: `8080`
     * 
     */
    @Export(name="port", type=Integer.class, parameters={})
    private Output<Integer> port;

    /**
     * @return The communication port for the backend server.  Example: `8080`
     * 
     */
    public Output<Integer> port() {
        return this.port;
    }
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    public Output<String> state() {
        return this.state;
    }
    /**
     * (Updatable) The load balancing policy weight assigned to the server. Backend servers with a higher weight receive a larger proportion of incoming traffic. For example, a server weighted &#39;3&#39; receives 3 times the number of new connections as a server weighted &#39;1&#39;. For more information on load balancing policies, see [How Load Balancing Policies Work](https://docs.cloud.oracle.com/iaas/Content/Balance/Reference/lbpolicies.htm).  Example: `3`
     * 
     */
    @Export(name="weight", type=Integer.class, parameters={})
    private Output<Integer> weight;

    /**
     * @return (Updatable) The load balancing policy weight assigned to the server. Backend servers with a higher weight receive a larger proportion of incoming traffic. For example, a server weighted &#39;3&#39; receives 3 times the number of new connections as a server weighted &#39;1&#39;. For more information on load balancing policies, see [How Load Balancing Policies Work](https://docs.cloud.oracle.com/iaas/Content/Balance/Reference/lbpolicies.htm).  Example: `3`
     * 
     */
    public Output<Integer> weight() {
        return this.weight;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public Backend(String name) {
        this(name, BackendArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public Backend(String name, BackendArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public Backend(String name, BackendArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:LoadBalancer/backend:Backend", name, args == null ? BackendArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private Backend(String name, Output<String> id, @Nullable BackendState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:LoadBalancer/backend:Backend", name, state, makeResourceOptions(options, id));
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
    public static Backend get(String name, Output<String> id, @Nullable BackendState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new Backend(name, id, state, options);
    }
}