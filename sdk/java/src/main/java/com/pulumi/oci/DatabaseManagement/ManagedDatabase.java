// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.DatabaseManagement.ManagedDatabaseArgs;
import com.pulumi.oci.DatabaseManagement.inputs.ManagedDatabaseState;
import com.pulumi.oci.DatabaseManagement.outputs.ManagedDatabaseDbmgmtFeatureConfig;
import com.pulumi.oci.DatabaseManagement.outputs.ManagedDatabaseManagedDatabaseGroup;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Managed Database resource in Oracle Cloud Infrastructure Database Management service.
 * 
 * Updates the Managed Database specified by managedDatabaseId.
 * 
 * ## Import
 * 
 * ManagedDatabases can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:DatabaseManagement/managedDatabase:ManagedDatabase test_managed_database &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:DatabaseManagement/managedDatabase:ManagedDatabase")
public class ManagedDatabase extends com.pulumi.resources.CustomResource {
    /**
     * The additional details specific to a type of database defined in `{&#34;key&#34;: &#34;value&#34;}` format. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="additionalDetails", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> additionalDetails;

    /**
     * @return The additional details specific to a type of database defined in `{&#34;key&#34;: &#34;value&#34;}` format. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,String>> additionalDetails() {
        return this.additionalDetails;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the Managed Database Group resides.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the Managed Database Group resides.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * The operating system of database.
     * 
     */
    @Export(name="databasePlatformName", refs={String.class}, tree="[0]")
    private Output<String> databasePlatformName;

    /**
     * @return The operating system of database.
     * 
     */
    public Output<String> databasePlatformName() {
        return this.databasePlatformName;
    }
    /**
     * The status of the Oracle Database. Indicates whether the status of the database is UP, DOWN, or UNKNOWN at the current time.
     * 
     */
    @Export(name="databaseStatus", refs={String.class}, tree="[0]")
    private Output<String> databaseStatus;

    /**
     * @return The status of the Oracle Database. Indicates whether the status of the database is UP, DOWN, or UNKNOWN at the current time.
     * 
     */
    public Output<String> databaseStatus() {
        return this.databaseStatus;
    }
    /**
     * The subtype of the Oracle Database. Indicates whether the database is a Container Database, Pluggable Database, Non-container Database, Autonomous Database, or Autonomous Container Database.
     * 
     */
    @Export(name="databaseSubType", refs={String.class}, tree="[0]")
    private Output<String> databaseSubType;

    /**
     * @return The subtype of the Oracle Database. Indicates whether the database is a Container Database, Pluggable Database, Non-container Database, Autonomous Database, or Autonomous Container Database.
     * 
     */
    public Output<String> databaseSubType() {
        return this.databaseSubType;
    }
    /**
     * The type of Oracle Database installation.
     * 
     */
    @Export(name="databaseType", refs={String.class}, tree="[0]")
    private Output<String> databaseType;

    /**
     * @return The type of Oracle Database installation.
     * 
     */
    public Output<String> databaseType() {
        return this.databaseType;
    }
    /**
     * The Oracle Database version.
     * 
     */
    @Export(name="databaseVersion", refs={String.class}, tree="[0]")
    private Output<String> databaseVersion;

    /**
     * @return The Oracle Database version.
     * 
     */
    public Output<String> databaseVersion() {
        return this.databaseVersion;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system that this Managed Database is part of.
     * 
     */
    @Export(name="dbSystemId", refs={String.class}, tree="[0]")
    private Output<String> dbSystemId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system that this Managed Database is part of.
     * 
     */
    public Output<String> dbSystemId() {
        return this.dbSystemId;
    }
    /**
     * The list of feature configurations
     * 
     */
    @Export(name="dbmgmtFeatureConfigs", refs={List.class,ManagedDatabaseDbmgmtFeatureConfig.class}, tree="[0,1]")
    private Output<List<ManagedDatabaseDbmgmtFeatureConfig>> dbmgmtFeatureConfigs;

    /**
     * @return The list of feature configurations
     * 
     */
    public Output<List<ManagedDatabaseDbmgmtFeatureConfig>> dbmgmtFeatureConfigs() {
        return this.dbmgmtFeatureConfigs;
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
     * The infrastructure used to deploy the Oracle Database.
     * 
     */
    @Export(name="deploymentType", refs={String.class}, tree="[0]")
    private Output<String> deploymentType;

    /**
     * @return The infrastructure used to deploy the Oracle Database.
     * 
     */
    public Output<String> deploymentType() {
        return this.deploymentType;
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
     * Indicates whether the Oracle Database is part of a cluster.
     * 
     */
    @Export(name="isCluster", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> isCluster;

    /**
     * @return Indicates whether the Oracle Database is part of a cluster.
     * 
     */
    public Output<Boolean> isCluster() {
        return this.isCluster;
    }
    /**
     * A list of Managed Database Groups that the Managed Database belongs to.
     * 
     */
    @Export(name="managedDatabaseGroups", refs={List.class,ManagedDatabaseManagedDatabaseGroup.class}, tree="[0,1]")
    private Output<List<ManagedDatabaseManagedDatabaseGroup>> managedDatabaseGroups;

    /**
     * @return A list of Managed Database Groups that the Managed Database belongs to.
     * 
     */
    public Output<List<ManagedDatabaseManagedDatabaseGroup>> managedDatabaseGroups() {
        return this.managedDatabaseGroups;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="managedDatabaseId", refs={String.class}, tree="[0]")
    private Output<String> managedDatabaseId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> managedDatabaseId() {
        return this.managedDatabaseId;
    }
    /**
     * The management option used when enabling Database Management.
     * 
     */
    @Export(name="managementOption", refs={String.class}, tree="[0]")
    private Output<String> managementOption;

    /**
     * @return The management option used when enabling Database Management.
     * 
     */
    public Output<String> managementOption() {
        return this.managementOption;
    }
    /**
     * The name of the Managed Database.
     * 
     */
    @Export(name="name", refs={String.class}, tree="[0]")
    private Output<String> name;

    /**
     * @return The name of the Managed Database.
     * 
     */
    public Output<String> name() {
        return this.name;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the parent Container Database if Managed Database is a Pluggable Database.
     * 
     */
    @Export(name="parentContainerId", refs={String.class}, tree="[0]")
    private Output<String> parentContainerId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the parent Container Database if Managed Database is a Pluggable Database.
     * 
     */
    public Output<String> parentContainerId() {
        return this.parentContainerId;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the storage DB system.
     * 
     */
    @Export(name="storageSystemId", refs={String.class}, tree="[0]")
    private Output<String> storageSystemId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the storage DB system.
     * 
     */
    public Output<String> storageSystemId() {
        return this.storageSystemId;
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
     * The date and time the Managed Database was created.
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The date and time the Managed Database was created.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The workload type of the Autonomous Database.
     * 
     */
    @Export(name="workloadType", refs={String.class}, tree="[0]")
    private Output<String> workloadType;

    /**
     * @return The workload type of the Autonomous Database.
     * 
     */
    public Output<String> workloadType() {
        return this.workloadType;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public ManagedDatabase(java.lang.String name) {
        this(name, ManagedDatabaseArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public ManagedDatabase(java.lang.String name, ManagedDatabaseArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public ManagedDatabase(java.lang.String name, ManagedDatabaseArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DatabaseManagement/managedDatabase:ManagedDatabase", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private ManagedDatabase(java.lang.String name, Output<java.lang.String> id, @Nullable ManagedDatabaseState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DatabaseManagement/managedDatabase:ManagedDatabase", name, state, makeResourceOptions(options, id), false);
    }

    private static ManagedDatabaseArgs makeArgs(ManagedDatabaseArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? ManagedDatabaseArgs.Empty : args;
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
    public static ManagedDatabase get(java.lang.String name, Output<java.lang.String> id, @Nullable ManagedDatabaseState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new ManagedDatabase(name, id, state, options);
    }
}
