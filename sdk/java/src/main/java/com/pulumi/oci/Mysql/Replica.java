// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Mysql.ReplicaArgs;
import com.pulumi.oci.Mysql.inputs.ReplicaState;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Replica resource in Oracle Cloud Infrastructure MySQL Database service.
 * 
 * Creates a DB System read replica.
 * 
 * ## Example Usage
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.Mysql.Replica;
 * import com.pulumi.oci.Mysql.ReplicaArgs;
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
 *         var testReplica = new Replica(&#34;testReplica&#34;, ReplicaArgs.builder()        
 *             .dbSystemId(oci_mysql_mysql_db_system.test_mysql_db_system().id())
 *             .definedTags(Map.of(&#34;foo-namespace.bar-key&#34;, &#34;value&#34;))
 *             .description(var_.replica_description())
 *             .displayName(var_.replica_display_name())
 *             .freeformTags(Map.of(&#34;bar-key&#34;, &#34;value&#34;))
 *             .isDeleteProtected(var_.replica_is_delete_protected())
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * Replicas can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:Mysql/replica:Replica test_replica &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Mysql/replica:Replica")
public class Replica extends com.pulumi.resources.CustomResource {
    /**
     * The name of the Availability Domain the read replica is located in.
     * 
     */
    @Export(name="availabilityDomain", type=String.class, parameters={})
    private Output<String> availabilityDomain;

    /**
     * @return The name of the Availability Domain the read replica is located in.
     * 
     */
    public Output<String> availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * The OCID of the compartment that contains the read replica.
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return The OCID of the compartment that contains the read replica.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * The OCID of the DB System the read replica is associated with.
     * 
     */
    @Export(name="dbSystemId", type=String.class, parameters={})
    private Output<String> dbSystemId;

    /**
     * @return The OCID of the DB System the read replica is associated with.
     * 
     */
    public Output<String> dbSystemId() {
        return this.dbSystemId;
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
     * (Updatable) User provided description of the read replica.
     * 
     */
    @Export(name="description", type=String.class, parameters={})
    private Output<String> description;

    /**
     * @return (Updatable) User provided description of the read replica.
     * 
     */
    public Output<String> description() {
        return this.description;
    }
    /**
     * (Updatable) The user-friendly name for the read replica. It does not have to be unique.
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return (Updatable) The user-friendly name for the read replica. It does not have to be unique.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * The name of the Fault Domain the read replica is located in.
     * 
     */
    @Export(name="faultDomain", type=String.class, parameters={})
    private Output<String> faultDomain;

    /**
     * @return The name of the Fault Domain the read replica is located in.
     * 
     */
    public Output<String> faultDomain() {
        return this.faultDomain;
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
     * The IP address the read replica is configured to listen on.
     * 
     */
    @Export(name="ipAddress", type=String.class, parameters={})
    private Output<String> ipAddress;

    /**
     * @return The IP address the read replica is configured to listen on.
     * 
     */
    public Output<String> ipAddress() {
        return this.ipAddress;
    }
    /**
     * (Updatable) Specifies whether the read replica can be deleted. Set to true to prevent deletion, false (default) to allow. Note that if a read replica is delete protected it also prevents the entire DB System from being deleted. If the DB System is delete protected, read replicas can still be deleted individually if they are not delete  protected themselves.
     * 
     */
    @Export(name="isDeleteProtected", type=Boolean.class, parameters={})
    private Output<Boolean> isDeleteProtected;

    /**
     * @return (Updatable) Specifies whether the read replica can be deleted. Set to true to prevent deletion, false (default) to allow. Note that if a read replica is delete protected it also prevents the entire DB System from being deleted. If the DB System is delete protected, read replicas can still be deleted individually if they are not delete  protected themselves.
     * 
     */
    public Output<Boolean> isDeleteProtected() {
        return this.isDeleteProtected;
    }
    /**
     * A message describing the state of the read replica.
     * 
     */
    @Export(name="lifecycleDetails", type=String.class, parameters={})
    private Output<String> lifecycleDetails;

    /**
     * @return A message describing the state of the read replica.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * The MySQL version used by the read replica.
     * 
     */
    @Export(name="mysqlVersion", type=String.class, parameters={})
    private Output<String> mysqlVersion;

    /**
     * @return The MySQL version used by the read replica.
     * 
     */
    public Output<String> mysqlVersion() {
        return this.mysqlVersion;
    }
    /**
     * The port the read replica is configured to listen on.
     * 
     */
    @Export(name="port", type=Integer.class, parameters={})
    private Output<Integer> port;

    /**
     * @return The port the read replica is configured to listen on.
     * 
     */
    public Output<Integer> port() {
        return this.port;
    }
    /**
     * The TCP network port on which X Plugin listens for connections. This is the X Plugin equivalent of port.
     * 
     */
    @Export(name="portX", type=Integer.class, parameters={})
    private Output<Integer> portX;

    /**
     * @return The TCP network port on which X Plugin listens for connections. This is the X Plugin equivalent of port.
     * 
     */
    public Output<Integer> portX() {
        return this.portX;
    }
    /**
     * The state of the read replica.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The state of the read replica.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The date and time the read replica was created, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The date and time the read replica was created, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time the read replica was last updated, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
     * 
     */
    @Export(name="timeUpdated", type=String.class, parameters={})
    private Output<String> timeUpdated;

    /**
     * @return The time the read replica was last updated, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public Replica(String name) {
        this(name, ReplicaArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public Replica(String name, ReplicaArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public Replica(String name, ReplicaArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Mysql/replica:Replica", name, args == null ? ReplicaArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private Replica(String name, Output<String> id, @Nullable ReplicaState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Mysql/replica:Replica", name, state, makeResourceOptions(options, id));
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
    public static Replica get(String name, Output<String> id, @Nullable ReplicaState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new Replica(name, id, state, options);
    }
}