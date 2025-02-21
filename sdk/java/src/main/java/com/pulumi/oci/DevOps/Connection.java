// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.DevOps.ConnectionArgs;
import com.pulumi.oci.DevOps.inputs.ConnectionState;
import com.pulumi.oci.DevOps.outputs.ConnectionLastConnectionValidationResult;
import com.pulumi.oci.DevOps.outputs.ConnectionTlsVerifyConfig;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Connection resource in Oracle Cloud Infrastructure Devops service.
 * 
 * Creates a new connection.
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
 * import com.pulumi.oci.DevOps.Connection;
 * import com.pulumi.oci.DevOps.ConnectionArgs;
 * import com.pulumi.oci.DevOps.inputs.ConnectionTlsVerifyConfigArgs;
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
 *         var testConnection = new Connection("testConnection", ConnectionArgs.builder()
 *             .connectionType(connectionConnectionType)
 *             .projectId(testProject.id())
 *             .accessToken(connectionAccessToken)
 *             .appPassword(connectionAppPassword)
 *             .baseUrl(connectionBaseUrl)
 *             .definedTags(Map.of("foo-namespace.bar-key", "value"))
 *             .description(connectionDescription)
 *             .displayName(connectionDisplayName)
 *             .freeformTags(Map.of("bar-key", "value"))
 *             .tlsVerifyConfig(ConnectionTlsVerifyConfigArgs.builder()
 *                 .caCertificateBundleId(testCaCertificateBundle.id())
 *                 .tlsVerifyMode(connectionTlsVerifyConfigTlsVerifyMode)
 *                 .build())
 *             .username(connectionUsername)
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
 * Connections can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:DevOps/connection:Connection test_connection &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:DevOps/connection:Connection")
public class Connection extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) The OCID of personal access token saved in secret store.
     * 
     */
    @Export(name="accessToken", refs={String.class}, tree="[0]")
    private Output<String> accessToken;

    /**
     * @return (Updatable) The OCID of personal access token saved in secret store.
     * 
     */
    public Output<String> accessToken() {
        return this.accessToken;
    }
    /**
     * (Updatable) OCID of personal Bitbucket Cloud AppPassword saved in secret store
     * 
     */
    @Export(name="appPassword", refs={String.class}, tree="[0]")
    private Output<String> appPassword;

    /**
     * @return (Updatable) OCID of personal Bitbucket Cloud AppPassword saved in secret store
     * 
     */
    public Output<String> appPassword() {
        return this.appPassword;
    }
    /**
     * (Updatable) The Base URL of the hosted BitbucketServer.
     * 
     */
    @Export(name="baseUrl", refs={String.class}, tree="[0]")
    private Output<String> baseUrl;

    /**
     * @return (Updatable) The Base URL of the hosted BitbucketServer.
     * 
     */
    public Output<String> baseUrl() {
        return this.baseUrl;
    }
    /**
     * The OCID of the compartment containing the connection.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return The OCID of the compartment containing the connection.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) The type of connection.
     * 
     */
    @Export(name="connectionType", refs={String.class}, tree="[0]")
    private Output<String> connectionType;

    /**
     * @return (Updatable) The type of connection.
     * 
     */
    public Output<String> connectionType() {
        return this.connectionType;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="definedTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,String>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) Optional description about the connection.
     * 
     */
    @Export(name="description", refs={String.class}, tree="[0]")
    private Output<String> description;

    /**
     * @return (Updatable) Optional description about the connection.
     * 
     */
    public Output<String> description() {
        return this.description;
    }
    /**
     * (Updatable) Optional connection display name. Avoid entering confidential information.
     * 
     */
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    /**
     * @return (Updatable) Optional connection display name. Avoid entering confidential information.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="freeformTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,String>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * The result of validating the credentials of a connection.
     * 
     */
    @Export(name="lastConnectionValidationResults", refs={List.class,ConnectionLastConnectionValidationResult.class}, tree="[0,1]")
    private Output<List<ConnectionLastConnectionValidationResult>> lastConnectionValidationResults;

    /**
     * @return The result of validating the credentials of a connection.
     * 
     */
    public Output<List<ConnectionLastConnectionValidationResult>> lastConnectionValidationResults() {
        return this.lastConnectionValidationResults;
    }
    /**
     * The OCID of the DevOps project.
     * 
     */
    @Export(name="projectId", refs={String.class}, tree="[0]")
    private Output<String> projectId;

    /**
     * @return The OCID of the DevOps project.
     * 
     */
    public Output<String> projectId() {
        return this.projectId;
    }
    /**
     * The current state of the connection.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current state of the connection.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Export(name="systemTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> systemTags;

    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Output<Map<String,String>> systemTags() {
        return this.systemTags;
    }
    /**
     * The time the connection was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The time the connection was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time the connection was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     * 
     */
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    /**
     * @return The time the connection was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * (Updatable) TLS configuration used by build service to verify TLS connection.
     * 
     */
    @Export(name="tlsVerifyConfig", refs={ConnectionTlsVerifyConfig.class}, tree="[0]")
    private Output<ConnectionTlsVerifyConfig> tlsVerifyConfig;

    /**
     * @return (Updatable) TLS configuration used by build service to verify TLS connection.
     * 
     */
    public Output<ConnectionTlsVerifyConfig> tlsVerifyConfig() {
        return this.tlsVerifyConfig;
    }
    /**
     * (Updatable) Public Bitbucket Cloud Username in plain text(not more than 30 characters)
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="username", refs={String.class}, tree="[0]")
    private Output<String> username;

    /**
     * @return (Updatable) Public Bitbucket Cloud Username in plain text(not more than 30 characters)
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> username() {
        return this.username;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public Connection(java.lang.String name) {
        this(name, ConnectionArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public Connection(java.lang.String name, ConnectionArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public Connection(java.lang.String name, ConnectionArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DevOps/connection:Connection", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private Connection(java.lang.String name, Output<java.lang.String> id, @Nullable ConnectionState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DevOps/connection:Connection", name, state, makeResourceOptions(options, id), false);
    }

    private static ConnectionArgs makeArgs(ConnectionArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? ConnectionArgs.Empty : args;
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<java.lang.String> id) {
        var defaultOptions = com.pulumi.resources.CustomResourceOptions.builder()
            .version(Utilities.getVersion())
            .additionalSecretOutputs(List.of(
                "appPassword"
            ))
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
    public static Connection get(java.lang.String name, Output<java.lang.String> id, @Nullable ConnectionState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new Connection(name, id, state, options);
    }
}
