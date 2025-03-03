// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseTools;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.DatabaseTools.DatabaseToolsConnectionArgs;
import com.pulumi.oci.DatabaseTools.inputs.DatabaseToolsConnectionState;
import com.pulumi.oci.DatabaseTools.outputs.DatabaseToolsConnectionKeyStore;
import com.pulumi.oci.DatabaseTools.outputs.DatabaseToolsConnectionLock;
import com.pulumi.oci.DatabaseTools.outputs.DatabaseToolsConnectionProxyClient;
import com.pulumi.oci.DatabaseTools.outputs.DatabaseToolsConnectionRelatedResource;
import com.pulumi.oci.DatabaseTools.outputs.DatabaseToolsConnectionUserPassword;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Database Tools Connection resource in Oracle Cloud Infrastructure Database Tools service.
 * 
 * Creates a new Database Tools connection.
 * 
 * ## Import
 * 
 * DatabaseToolsConnections can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:DatabaseTools/databaseToolsConnection:DatabaseToolsConnection test_database_tools_connection &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:DatabaseTools/databaseToolsConnection:DatabaseToolsConnection")
public class DatabaseToolsConnection extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) The advanced connection properties key-value pair (e.g., `oracle.net.ssl_server_dn_match`).
     * 
     */
    @Export(name="advancedProperties", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> advancedProperties;

    /**
     * @return (Updatable) The advanced connection properties key-value pair (e.g., `oracle.net.ssl_server_dn_match`).
     * 
     */
    public Output<Map<String,String>> advancedProperties() {
        return this.advancedProperties;
    }
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Database Tools connection.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Database Tools connection.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) The connect descriptor or Easy Connect Naming method use to connect to the database.
     * 
     */
    @Export(name="connectionString", refs={String.class}, tree="[0]")
    private Output<String> connectionString;

    /**
     * @return (Updatable) The connect descriptor or Easy Connect Naming method use to connect to the database.
     * 
     */
    public Output<String> connectionString() {
        return this.connectionString;
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
     * (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
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
     * (Updatable) Oracle wallet or Java Keystores containing trusted certificates for authenticating the server&#39;s public certificate and the client private key and associated certificates required for client authentication.
     * 
     */
    @Export(name="keyStores", refs={List.class,DatabaseToolsConnectionKeyStore.class}, tree="[0,1]")
    private Output<List<DatabaseToolsConnectionKeyStore>> keyStores;

    /**
     * @return (Updatable) Oracle wallet or Java Keystores containing trusted certificates for authenticating the server&#39;s public certificate and the client private key and associated certificates required for client authentication.
     * 
     */
    public Output<List<DatabaseToolsConnectionKeyStore>> keyStores() {
        return this.keyStores;
    }
    /**
     * A message describing the current state in more detail. For example, this message can be used to provide actionable information for a resource in the Failed state.
     * 
     */
    @Export(name="lifecycleDetails", refs={String.class}, tree="[0]")
    private Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail. For example, this message can be used to provide actionable information for a resource in the Failed state.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * Locks associated with this resource.
     * 
     */
    @Export(name="locks", refs={List.class,DatabaseToolsConnectionLock.class}, tree="[0,1]")
    private Output<List<DatabaseToolsConnectionLock>> locks;

    /**
     * @return Locks associated with this resource.
     * 
     */
    public Output<List<DatabaseToolsConnectionLock>> locks() {
        return this.locks;
    }
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Tools private endpoint used to access the database in the customer VCN.
     * 
     */
    @Export(name="privateEndpointId", refs={String.class}, tree="[0]")
    private Output<String> privateEndpointId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Tools private endpoint used to access the database in the customer VCN.
     * 
     */
    public Output<String> privateEndpointId() {
        return this.privateEndpointId;
    }
    /**
     * (Updatable) The proxy client information.
     * 
     */
    @Export(name="proxyClient", refs={DatabaseToolsConnectionProxyClient.class}, tree="[0]")
    private Output<DatabaseToolsConnectionProxyClient> proxyClient;

    /**
     * @return (Updatable) The proxy client information.
     * 
     */
    public Output<DatabaseToolsConnectionProxyClient> proxyClient() {
        return this.proxyClient;
    }
    /**
     * (Updatable) The related resource
     * 
     */
    @Export(name="relatedResource", refs={DatabaseToolsConnectionRelatedResource.class}, tree="[0]")
    private Output<DatabaseToolsConnectionRelatedResource> relatedResource;

    /**
     * @return (Updatable) The related resource
     * 
     */
    public Output<DatabaseToolsConnectionRelatedResource> relatedResource() {
        return this.relatedResource;
    }
    /**
     * Specifies whether this connection is supported by the Database Tools Runtime.
     * 
     */
    @Export(name="runtimeSupport", refs={String.class}, tree="[0]")
    private Output<String> runtimeSupport;

    /**
     * @return Specifies whether this connection is supported by the Database Tools Runtime.
     * 
     */
    public Output<String> runtimeSupport() {
        return this.runtimeSupport;
    }
    /**
     * The current state of the Database Tools connection.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current state of the Database Tools connection.
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
     * The time the Database Tools connection was created. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The time the Database Tools connection was created. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time the DatabaseToolsConnection was updated. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    /**
     * @return The time the DatabaseToolsConnection was updated. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * (Updatable) The DatabaseToolsConnection type.
     * 
     */
    @Export(name="type", refs={String.class}, tree="[0]")
    private Output<String> type;

    /**
     * @return (Updatable) The DatabaseToolsConnection type.
     * 
     */
    public Output<String> type() {
        return this.type;
    }
    /**
     * (Updatable) The JDBC URL used to connect to the Generic JDBC database system.
     * 
     */
    @Export(name="url", refs={String.class}, tree="[0]")
    private Output<String> url;

    /**
     * @return (Updatable) The JDBC URL used to connect to the Generic JDBC database system.
     * 
     */
    public Output<String> url() {
        return this.url;
    }
    /**
     * (Updatable) The database user name.
     * 
     */
    @Export(name="userName", refs={String.class}, tree="[0]")
    private Output<String> userName;

    /**
     * @return (Updatable) The database user name.
     * 
     */
    public Output<String> userName() {
        return this.userName;
    }
    /**
     * (Updatable) The user password.
     * 
     */
    @Export(name="userPassword", refs={DatabaseToolsConnectionUserPassword.class}, tree="[0]")
    private Output<DatabaseToolsConnectionUserPassword> userPassword;

    /**
     * @return (Updatable) The user password.
     * 
     */
    public Output<DatabaseToolsConnectionUserPassword> userPassword() {
        return this.userPassword;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public DatabaseToolsConnection(java.lang.String name) {
        this(name, DatabaseToolsConnectionArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public DatabaseToolsConnection(java.lang.String name, DatabaseToolsConnectionArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public DatabaseToolsConnection(java.lang.String name, DatabaseToolsConnectionArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DatabaseTools/databaseToolsConnection:DatabaseToolsConnection", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private DatabaseToolsConnection(java.lang.String name, Output<java.lang.String> id, @Nullable DatabaseToolsConnectionState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DatabaseTools/databaseToolsConnection:DatabaseToolsConnection", name, state, makeResourceOptions(options, id), false);
    }

    private static DatabaseToolsConnectionArgs makeArgs(DatabaseToolsConnectionArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? DatabaseToolsConnectionArgs.Empty : args;
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
    public static DatabaseToolsConnection get(java.lang.String name, Output<java.lang.String> id, @Nullable DatabaseToolsConnectionState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new DatabaseToolsConnection(name, id, state, options);
    }
}
