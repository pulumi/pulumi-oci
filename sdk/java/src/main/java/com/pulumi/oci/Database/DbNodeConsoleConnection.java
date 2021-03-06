// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Database.DbNodeConsoleConnectionArgs;
import com.pulumi.oci.Database.inputs.DbNodeConsoleConnectionState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import javax.annotation.Nullable;

/**
 * This resource provides the Db Node Console Connection resource in Oracle Cloud Infrastructure Database service.
 * 
 * Creates a new console connection to the specified database node.
 * After the console connection has been created and is available,
 * you connect to the console using SSH.
 * 
 * ## Example Usage
 * 
 * ## Import
 * 
 * DbNodeConsoleConnections can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:Database/dbNodeConsoleConnection:DbNodeConsoleConnection test_db_node_console_connection &#34;dbNodes/{dbNodeId}/consoleConnections/{consoleConnectionId}&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Database/dbNodeConsoleConnection:DbNodeConsoleConnection")
public class DbNodeConsoleConnection extends com.pulumi.resources.CustomResource {
    /**
     * The OCID of the compartment to contain the console connection.
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return The OCID of the compartment to contain the console connection.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * The SSH connection string for the console connection.
     * 
     */
    @Export(name="connectionString", type=String.class, parameters={})
    private Output<String> connectionString;

    /**
     * @return The SSH connection string for the console connection.
     * 
     */
    public Output<String> connectionString() {
        return this.connectionString;
    }
    /**
     * The database node [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Export(name="dbNodeId", type=String.class, parameters={})
    private Output<String> dbNodeId;

    /**
     * @return The database node [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Output<String> dbNodeId() {
        return this.dbNodeId;
    }
    /**
     * The SSH public key fingerprint for the console connection.
     * 
     */
    @Export(name="fingerprint", type=String.class, parameters={})
    private Output<String> fingerprint;

    /**
     * @return The SSH public key fingerprint for the console connection.
     * 
     */
    public Output<String> fingerprint() {
        return this.fingerprint;
    }
    /**
     * The SSH public key used to authenticate the console connection.
     * 
     */
    @Export(name="publicKey", type=String.class, parameters={})
    private Output<String> publicKey;

    /**
     * @return The SSH public key used to authenticate the console connection.
     * 
     */
    public Output<String> publicKey() {
        return this.publicKey;
    }
    /**
     * The current state of the console connection.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current state of the console connection.
     * 
     */
    public Output<String> state() {
        return this.state;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public DbNodeConsoleConnection(String name) {
        this(name, DbNodeConsoleConnectionArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public DbNodeConsoleConnection(String name, DbNodeConsoleConnectionArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public DbNodeConsoleConnection(String name, DbNodeConsoleConnectionArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Database/dbNodeConsoleConnection:DbNodeConsoleConnection", name, args == null ? DbNodeConsoleConnectionArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private DbNodeConsoleConnection(String name, Output<String> id, @Nullable DbNodeConsoleConnectionState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Database/dbNodeConsoleConnection:DbNodeConsoleConnection", name, state, makeResourceOptions(options, id));
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
    public static DbNodeConsoleConnection get(String name, Output<String> id, @Nullable DbNodeConsoleConnectionState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new DbNodeConsoleConnection(name, id, state, options);
    }
}
