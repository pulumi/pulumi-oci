// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Database.CloudDatabaseManagementArgs;
import com.pulumi.oci.Database.inputs.CloudDatabaseManagementState;
import com.pulumi.oci.Database.outputs.CloudDatabaseManagementCredentialdetails;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * This resource provides the Database Management resource in Oracle Cloud Infrastructure Database service.
 * 
 * Enable / Update / Disable database management for the specified Oracle Database instance.
 * 
 * Database Management requires `USER_NAME`, `PASSWORD_SECRET_ID` and `PRIVATE_END_POINT_ID`.
 * `database.0.database_management_config` is updated to appropriate managementType and managementStatus for the specified Oracle Database instance.
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
 * import com.pulumi.oci.Database.CloudDatabaseManagement;
 * import com.pulumi.oci.Database.CloudDatabaseManagementArgs;
 * import com.pulumi.oci.Database.inputs.CloudDatabaseManagementCredentialdetailsArgs;
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
 *         var test = new CloudDatabaseManagement("test", CloudDatabaseManagementArgs.builder()
 *             .databaseId(testDatabase.id())
 *             .managementType(databaseCloudDatabaseManagementDetailsManagementType)
 *             .privateEndPointId(databaseCloudDatabaseManagementDetailsPrivateEndPointId)
 *             .serviceName(databaseCloudDatabaseManagementDetailsServiceName)
 *             .credentialdetails(CloudDatabaseManagementCredentialdetailsArgs.builder()
 *                 .userName(databaseCloudDatabaseManagementDetailsUserName)
 *                 .passwordSecretId(databaseCloudDatabaseManagementDetailsPasswordSecretId)
 *                 .build())
 *             .enableManagement(databaseCloudDatabaseManagementDetailsEnableManagement)
 *             .port(cloudDatabaseManagementPort)
 *             .protocol(cloudDatabaseManagementProtocol)
 *             .role(cloudDatabaseManagementRole)
 *             .sslSecretId(testSecret.id())
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
 * Import is not supported for this resource.
 * 
 */
@ResourceType(type="oci:Database/cloudDatabaseManagement:CloudDatabaseManagement")
public class CloudDatabaseManagement extends com.pulumi.resources.CustomResource {
    @Export(name="credentialdetails", refs={CloudDatabaseManagementCredentialdetails.class}, tree="[0]")
    private Output<CloudDatabaseManagementCredentialdetails> credentialdetails;

    public Output<CloudDatabaseManagementCredentialdetails> credentialdetails() {
        return this.credentialdetails;
    }
    /**
     * The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Export(name="databaseId", refs={String.class}, tree="[0]")
    private Output<String> databaseId;

    /**
     * @return The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Output<String> databaseId() {
        return this.databaseId;
    }
    /**
     * (Updatable) Use this flag to enable/disable database management
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="enableManagement", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> enableManagement;

    /**
     * @return (Updatable) Use this flag to enable/disable database management
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<Boolean> enableManagement() {
        return this.enableManagement;
    }
    /**
     * (Updatable) Specifies database management type
     * enum:
     * - `BASIC`
     * - `ADVANCED`
     * 
     */
    @Export(name="managementType", refs={String.class}, tree="[0]")
    private Output<String> managementType;

    /**
     * @return (Updatable) Specifies database management type
     * enum:
     * - `BASIC`
     * - `ADVANCED`
     * 
     */
    public Output<String> managementType() {
        return this.managementType;
    }
    /**
     * The port used to connect to the database.
     * 
     */
    @Export(name="port", refs={Integer.class}, tree="[0]")
    private Output</* @Nullable */ Integer> port;

    /**
     * @return The port used to connect to the database.
     * 
     */
    public Output<Optional<Integer>> port() {
        return Codegen.optional(this.port);
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the private endpoint.
     * 
     */
    @Export(name="privateEndPointId", refs={String.class}, tree="[0]")
    private Output<String> privateEndPointId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the private endpoint.
     * 
     */
    public Output<String> privateEndPointId() {
        return this.privateEndPointId;
    }
    /**
     * Protocol used by the database connection.
     * 
     */
    @Export(name="protocol", refs={String.class}, tree="[0]")
    private Output</* @Nullable */ String> protocol;

    /**
     * @return Protocol used by the database connection.
     * 
     */
    public Output<Optional<String>> protocol() {
        return Codegen.optional(this.protocol);
    }
    /**
     * The role of the user that will be connecting to the database.
     * 
     */
    @Export(name="role", refs={String.class}, tree="[0]")
    private Output</* @Nullable */ String> role;

    /**
     * @return The role of the user that will be connecting to the database.
     * 
     */
    public Output<Optional<String>> role() {
        return Codegen.optional(this.role);
    }
    /**
     * The name of the Oracle Database service that will be used to connect to the database.
     * 
     */
    @Export(name="serviceName", refs={String.class}, tree="[0]")
    private Output<String> serviceName;

    /**
     * @return The name of the Oracle Database service that will be used to connect to the database.
     * 
     */
    public Output<String> serviceName() {
        return this.serviceName;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [secret](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts).
     * 
     */
    @Export(name="sslSecretId", refs={String.class}, tree="[0]")
    private Output</* @Nullable */ String> sslSecretId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [secret](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts).
     * 
     */
    public Output<Optional<String>> sslSecretId() {
        return Codegen.optional(this.sslSecretId);
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public CloudDatabaseManagement(java.lang.String name) {
        this(name, CloudDatabaseManagementArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public CloudDatabaseManagement(java.lang.String name, CloudDatabaseManagementArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public CloudDatabaseManagement(java.lang.String name, CloudDatabaseManagementArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Database/cloudDatabaseManagement:CloudDatabaseManagement", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private CloudDatabaseManagement(java.lang.String name, Output<java.lang.String> id, @Nullable CloudDatabaseManagementState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Database/cloudDatabaseManagement:CloudDatabaseManagement", name, state, makeResourceOptions(options, id), false);
    }

    private static CloudDatabaseManagementArgs makeArgs(CloudDatabaseManagementArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? CloudDatabaseManagementArgs.Empty : args;
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
    public static CloudDatabaseManagement get(java.lang.String name, Output<java.lang.String> id, @Nullable CloudDatabaseManagementState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new CloudDatabaseManagement(name, id, state, options);
    }
}
