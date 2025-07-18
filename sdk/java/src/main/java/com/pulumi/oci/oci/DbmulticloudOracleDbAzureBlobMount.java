// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.oci;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Utilities;
import com.pulumi.oci.oci.DbmulticloudOracleDbAzureBlobMountArgs;
import com.pulumi.oci.oci.inputs.DbmulticloudOracleDbAzureBlobMountState;
import java.lang.String;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Oracle Db Azure Blob Mount resource in Oracle Cloud Infrastructure Dbmulticloud service.
 * 
 * Creates Oracle DB Azure Blob Mount resource and mounts Azure Container in Oracle Cloud Infrastructure Database Resource,
 * based on provided Azure Container details and Database Resource ID.
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
 * import com.pulumi.oci.oci.DbmulticloudOracleDbAzureBlobMount;
 * import com.pulumi.oci.oci.DbmulticloudOracleDbAzureBlobMountArgs;
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
 *         var testOracleDbAzureBlobMount = new DbmulticloudOracleDbAzureBlobMount("testOracleDbAzureBlobMount", DbmulticloudOracleDbAzureBlobMountArgs.builder()
 *             .compartmentId(compartmentId)
 *             .displayName(oracleDbAzureBlobMountDisplayName)
 *             .oracleDbAzureBlobContainerId(testOracleDbAzureBlobContainer.id())
 *             .oracleDbAzureConnectorId(testOracleDbAzureConnector.id())
 *             .definedTags(Map.of("Operations.CostCenter", "42"))
 *             .freeformTags(Map.of("Department", "Finance"))
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
 * OracleDbAzureBlobMounts can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:oci/dbmulticloudOracleDbAzureBlobMount:DbmulticloudOracleDbAzureBlobMount test_oracle_db_azure_blob_mount &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:oci/dbmulticloudOracleDbAzureBlobMount:DbmulticloudOracleDbAzureBlobMount")
public class DbmulticloudOracleDbAzureBlobMount extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) The OCID of the compartment that contains VMs where to mount Azure Container.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the compartment that contains VMs where to mount Azure Container.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Export(name="definedTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Output<Map<String,String>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) Oracle DB Azure Blob Mount Resource name.
     * 
     */
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    /**
     * @return (Updatable) Oracle DB Azure Blob Mount Resource name.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Export(name="freeformTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Output<Map<String,String>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * Description of the latest modification of the Oracle DB Azure Blob Mount Resource.
     * 
     */
    @Export(name="lastModification", refs={String.class}, tree="[0]")
    private Output<String> lastModification;

    /**
     * @return Description of the latest modification of the Oracle DB Azure Blob Mount Resource.
     * 
     */
    public Output<String> lastModification() {
        return this.lastModification;
    }
    /**
     * Description of the current lifecycle state in more detail.
     * 
     */
    @Export(name="lifecycleStateDetails", refs={String.class}, tree="[0]")
    private Output<String> lifecycleStateDetails;

    /**
     * @return Description of the current lifecycle state in more detail.
     * 
     */
    public Output<String> lifecycleStateDetails() {
        return this.lifecycleStateDetails;
    }
    /**
     * Azure Container mount path.
     * 
     */
    @Export(name="mountPath", refs={String.class}, tree="[0]")
    private Output<String> mountPath;

    /**
     * @return Azure Container mount path.
     * 
     */
    public Output<String> mountPath() {
        return this.mountPath;
    }
    /**
     * (Updatable) The OCID of the Oracle DB Azure Blob Container Resource.
     * 
     */
    @Export(name="oracleDbAzureBlobContainerId", refs={String.class}, tree="[0]")
    private Output<String> oracleDbAzureBlobContainerId;

    /**
     * @return (Updatable) The OCID of the Oracle DB Azure Blob Container Resource.
     * 
     */
    public Output<String> oracleDbAzureBlobContainerId() {
        return this.oracleDbAzureBlobContainerId;
    }
    /**
     * (Updatable) The OCID of the Oracle DB Azure Connector Resource.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="oracleDbAzureConnectorId", refs={String.class}, tree="[0]")
    private Output<String> oracleDbAzureConnectorId;

    /**
     * @return (Updatable) The OCID of the Oracle DB Azure Connector Resource.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> oracleDbAzureConnectorId() {
        return this.oracleDbAzureConnectorId;
    }
    /**
     * The current lifecycle state of the Azure Arc Agent Resource.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current lifecycle state of the Azure Arc Agent Resource.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Export(name="systemTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> systemTags;

    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Output<Map<String,String>> systemTags() {
        return this.systemTags;
    }
    /**
     * Time when the Oracle DB Azure Blob Mount was created in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. &#39;2020-05-22T21:10:29.600Z&#39;
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return Time when the Oracle DB Azure Blob Mount was created in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. &#39;2020-05-22T21:10:29.600Z&#39;
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * Time when the Oracle DB Azure Blob Mount was last modified, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. &#39;2020-05-22T21:10:29.600Z&#39;
     * 
     */
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    /**
     * @return Time when the Oracle DB Azure Blob Mount was last modified, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. &#39;2020-05-22T21:10:29.600Z&#39;
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public DbmulticloudOracleDbAzureBlobMount(java.lang.String name) {
        this(name, DbmulticloudOracleDbAzureBlobMountArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public DbmulticloudOracleDbAzureBlobMount(java.lang.String name, DbmulticloudOracleDbAzureBlobMountArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public DbmulticloudOracleDbAzureBlobMount(java.lang.String name, DbmulticloudOracleDbAzureBlobMountArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:oci/dbmulticloudOracleDbAzureBlobMount:DbmulticloudOracleDbAzureBlobMount", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private DbmulticloudOracleDbAzureBlobMount(java.lang.String name, Output<java.lang.String> id, @Nullable DbmulticloudOracleDbAzureBlobMountState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:oci/dbmulticloudOracleDbAzureBlobMount:DbmulticloudOracleDbAzureBlobMount", name, state, makeResourceOptions(options, id), false);
    }

    private static DbmulticloudOracleDbAzureBlobMountArgs makeArgs(DbmulticloudOracleDbAzureBlobMountArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? DbmulticloudOracleDbAzureBlobMountArgs.Empty : args;
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
    public static DbmulticloudOracleDbAzureBlobMount get(java.lang.String name, Output<java.lang.String> id, @Nullable DbmulticloudOracleDbAzureBlobMountState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new DbmulticloudOracleDbAzureBlobMount(name, id, state, options);
    }
}
