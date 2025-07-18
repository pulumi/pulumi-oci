// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.oci;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Utilities;
import com.pulumi.oci.oci.DbmulticloudMultiCloudResourceDiscoveryArgs;
import com.pulumi.oci.oci.inputs.DbmulticloudMultiCloudResourceDiscoveryState;
import com.pulumi.oci.oci.outputs.DbmulticloudMultiCloudResourceDiscoveryResource;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Multi Cloud Resource Discovery resource in Oracle Cloud Infrastructure Dbmulticloud service.
 * 
 * Discover Azure Vaults and Keys based on the provided information.
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
 * import com.pulumi.oci.oci.DbmulticloudMultiCloudResourceDiscovery;
 * import com.pulumi.oci.oci.DbmulticloudMultiCloudResourceDiscoveryArgs;
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
 *         var testMultiCloudResourceDiscovery = new DbmulticloudMultiCloudResourceDiscovery("testMultiCloudResourceDiscovery", DbmulticloudMultiCloudResourceDiscoveryArgs.builder()
 *             .compartmentId(compartmentId)
 *             .displayName(multiCloudResourceDiscoveryDisplayName)
 *             .oracleDbConnectorId(testOracleDbConnector.id())
 *             .resourceType(multiCloudResourceDiscoveryResourceType)
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
 * MultiCloudResourceDiscoveries can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:oci/dbmulticloudMultiCloudResourceDiscovery:DbmulticloudMultiCloudResourceDiscovery test_multi_cloud_resource_discovery &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:oci/dbmulticloudMultiCloudResourceDiscovery:DbmulticloudMultiCloudResourceDiscovery")
public class DbmulticloudMultiCloudResourceDiscovery extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains Discovered Resource.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains Discovered Resource.
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
     * (Updatable) Display name of Discovered Resource.
     * 
     */
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    /**
     * @return (Updatable) Display name of Discovered Resource.
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
     * Description of the latest modification of the Multi Cloud Discovery Resource.
     * 
     */
    @Export(name="lastModification", refs={String.class}, tree="[0]")
    private Output<String> lastModification;

    /**
     * @return Description of the latest modification of the Multi Cloud Discovery Resource.
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
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of Oracle DB Connector.
     * 
     */
    @Export(name="oracleDbConnectorId", refs={String.class}, tree="[0]")
    private Output<String> oracleDbConnectorId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of Oracle DB Connector.
     * 
     */
    public Output<String> oracleDbConnectorId() {
        return this.oracleDbConnectorId;
    }
    /**
     * (Updatable) Resource Type to discover.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="resourceType", refs={String.class}, tree="[0]")
    private Output<String> resourceType;

    /**
     * @return (Updatable) Resource Type to discover.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> resourceType() {
        return this.resourceType;
    }
    /**
     * List of All Discovered resources.
     * 
     */
    @Export(name="resources", refs={List.class,DbmulticloudMultiCloudResourceDiscoveryResource.class}, tree="[0,1]")
    private Output<List<DbmulticloudMultiCloudResourceDiscoveryResource>> resources;

    /**
     * @return List of All Discovered resources.
     * 
     */
    public Output<List<DbmulticloudMultiCloudResourceDiscoveryResource>> resources() {
        return this.resources;
    }
    /**
     * The current lifecycle state of the discovered resource.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current lifecycle state of the discovered resource.
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
     * Time when the Multi Cloud Discovery Resource was created in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. &#39;2020-05-22T21:10:29.600Z&#39;
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return Time when the Multi Cloud Discovery Resource was created in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. &#39;2020-05-22T21:10:29.600Z&#39;
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * Time when the Multi Cloud Discovery Resource was last modified, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. &#39;2020-05-22T21:10:29.600Z&#39;
     * 
     */
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    /**
     * @return Time when the Multi Cloud Discovery Resource was last modified, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. &#39;2020-05-22T21:10:29.600Z&#39;
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public DbmulticloudMultiCloudResourceDiscovery(java.lang.String name) {
        this(name, DbmulticloudMultiCloudResourceDiscoveryArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public DbmulticloudMultiCloudResourceDiscovery(java.lang.String name, DbmulticloudMultiCloudResourceDiscoveryArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public DbmulticloudMultiCloudResourceDiscovery(java.lang.String name, DbmulticloudMultiCloudResourceDiscoveryArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:oci/dbmulticloudMultiCloudResourceDiscovery:DbmulticloudMultiCloudResourceDiscovery", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private DbmulticloudMultiCloudResourceDiscovery(java.lang.String name, Output<java.lang.String> id, @Nullable DbmulticloudMultiCloudResourceDiscoveryState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:oci/dbmulticloudMultiCloudResourceDiscovery:DbmulticloudMultiCloudResourceDiscovery", name, state, makeResourceOptions(options, id), false);
    }

    private static DbmulticloudMultiCloudResourceDiscoveryArgs makeArgs(DbmulticloudMultiCloudResourceDiscoveryArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? DbmulticloudMultiCloudResourceDiscoveryArgs.Empty : args;
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
    public static DbmulticloudMultiCloudResourceDiscovery get(java.lang.String name, Output<java.lang.String> id, @Nullable DbmulticloudMultiCloudResourceDiscoveryState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new DbmulticloudMultiCloudResourceDiscovery(name, id, state, options);
    }
}
