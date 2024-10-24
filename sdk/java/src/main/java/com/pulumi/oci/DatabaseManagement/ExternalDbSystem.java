// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.DatabaseManagement.ExternalDbSystemArgs;
import com.pulumi.oci.DatabaseManagement.inputs.ExternalDbSystemState;
import com.pulumi.oci.DatabaseManagement.outputs.ExternalDbSystemDatabaseManagementConfig;
import com.pulumi.oci.DatabaseManagement.outputs.ExternalDbSystemStackMonitoringConfig;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.String;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the External Db System resource in Oracle Cloud Infrastructure Database Management service.
 * 
 * Creates an external DB system and its related resources.
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
 * import com.pulumi.oci.DatabaseManagement.ExternalDbSystem;
 * import com.pulumi.oci.DatabaseManagement.ExternalDbSystemArgs;
 * import com.pulumi.oci.DatabaseManagement.inputs.ExternalDbSystemDatabaseManagementConfigArgs;
 * import com.pulumi.oci.DatabaseManagement.inputs.ExternalDbSystemStackMonitoringConfigArgs;
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
 *         var testExternalDbSystem = new ExternalDbSystem("testExternalDbSystem", ExternalDbSystemArgs.builder()
 *             .compartmentId(compartmentId)
 *             .dbSystemDiscoveryId(testDbSystemDiscovery.id())
 *             .databaseManagementConfig(ExternalDbSystemDatabaseManagementConfigArgs.builder()
 *                 .licenseModel(externalDbSystemDatabaseManagementConfigLicenseModel)
 *                 .build())
 *             .definedTags(Map.of("Operations.CostCenter", "42"))
 *             .displayName(externalDbSystemDisplayName)
 *             .freeformTags(Map.of("Department", "Finance"))
 *             .stackMonitoringConfig(ExternalDbSystemStackMonitoringConfigArgs.builder()
 *                 .isEnabled(externalDbSystemStackMonitoringConfigIsEnabled)
 *                 .metadata(externalDbSystemStackMonitoringConfigMetadata)
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
 * ExternalDbSystems can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:DatabaseManagement/externalDbSystem:ExternalDbSystem test_external_db_system &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:DatabaseManagement/externalDbSystem:ExternalDbSystem")
public class ExternalDbSystem extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external DB system resides.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external DB system resides.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * The details required to enable Database Management for an external DB system.
     * 
     */
    @Export(name="databaseManagementConfig", refs={ExternalDbSystemDatabaseManagementConfig.class}, tree="[0]")
    private Output<ExternalDbSystemDatabaseManagementConfig> databaseManagementConfig;

    /**
     * @return The details required to enable Database Management for an external DB system.
     * 
     */
    public Output<ExternalDbSystemDatabaseManagementConfig> databaseManagementConfig() {
        return this.databaseManagementConfig;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system discovery.
     * 
     */
    @Export(name="dbSystemDiscoveryId", refs={String.class}, tree="[0]")
    private Output<String> dbSystemDiscoveryId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system discovery.
     * 
     */
    public Output<String> dbSystemDiscoveryId() {
        return this.dbSystemDiscoveryId;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Export(name="definedTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Output<Map<String,String>> definedTags() {
        return this.definedTags;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management agent used during the discovery of the DB system.
     * 
     */
    @Export(name="discoveryAgentId", refs={String.class}, tree="[0]")
    private Output<String> discoveryAgentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management agent used during the discovery of the DB system.
     * 
     */
    public Output<String> discoveryAgentId() {
        return this.discoveryAgentId;
    }
    /**
     * (Updatable) The user-friendly name for the DB system. The name does not have to be unique.
     * 
     */
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    /**
     * @return (Updatable) The user-friendly name for the DB system. The name does not have to be unique.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Export(name="freeformTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Output<Map<String,String>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * The Oracle Grid home directory in case of cluster-based DB system and Oracle home directory in case of single instance-based DB system.
     * 
     */
    @Export(name="homeDirectory", refs={String.class}, tree="[0]")
    private Output<String> homeDirectory;

    /**
     * @return The Oracle Grid home directory in case of cluster-based DB system and Oracle home directory in case of single instance-based DB system.
     * 
     */
    public Output<String> homeDirectory() {
        return this.homeDirectory;
    }
    /**
     * Indicates whether the DB system is a cluster DB system or not.
     * 
     */
    @Export(name="isCluster", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> isCluster;

    /**
     * @return Indicates whether the DB system is a cluster DB system or not.
     * 
     */
    public Output<Boolean> isCluster() {
        return this.isCluster;
    }
    /**
     * Additional information about the current lifecycle state.
     * 
     */
    @Export(name="lifecycleDetails", refs={String.class}, tree="[0]")
    private Output<String> lifecycleDetails;

    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * The details of the associated service that will be enabled or disabled for an external DB System.
     * 
     */
    @Export(name="stackMonitoringConfig", refs={ExternalDbSystemStackMonitoringConfig.class}, tree="[0]")
    private Output<ExternalDbSystemStackMonitoringConfig> stackMonitoringConfig;

    /**
     * @return The details of the associated service that will be enabled or disabled for an external DB System.
     * 
     */
    public Output<ExternalDbSystemStackMonitoringConfig> stackMonitoringConfig() {
        return this.stackMonitoringConfig;
    }
    /**
     * The current lifecycle state of the external DB system resource.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current lifecycle state of the external DB system resource.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Export(name="systemTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> systemTags;

    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Output<Map<String,String>> systemTags() {
        return this.systemTags;
    }
    /**
     * The date and time the external DB system was created.
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The date and time the external DB system was created.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The date and time the external DB system was last updated.
     * 
     */
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    /**
     * @return The date and time the external DB system was last updated.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public ExternalDbSystem(java.lang.String name) {
        this(name, ExternalDbSystemArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public ExternalDbSystem(java.lang.String name, ExternalDbSystemArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public ExternalDbSystem(java.lang.String name, ExternalDbSystemArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DatabaseManagement/externalDbSystem:ExternalDbSystem", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private ExternalDbSystem(java.lang.String name, Output<java.lang.String> id, @Nullable ExternalDbSystemState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DatabaseManagement/externalDbSystem:ExternalDbSystem", name, state, makeResourceOptions(options, id), false);
    }

    private static ExternalDbSystemArgs makeArgs(ExternalDbSystemArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? ExternalDbSystemArgs.Empty : args;
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
    public static ExternalDbSystem get(java.lang.String name, Output<java.lang.String> id, @Nullable ExternalDbSystemState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new ExternalDbSystem(name, id, state, options);
    }
}
