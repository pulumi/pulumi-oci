// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Database.DbHomeArgs;
import com.pulumi.oci.Database.inputs.DbHomeState;
import com.pulumi.oci.Database.outputs.DbHomeDatabase;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.String;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * ## Example Usage
 * 
 * &lt;!--Start PulumiCodeChooser --&gt;
 * &lt;!--End PulumiCodeChooser --&gt;
 * 
 * ## Import
 * 
 * DbHomes can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:Database/dbHome:DbHome test_db_home &#34;id&#34;
 * ```
 * 
 * Import is only supported for source=NONE
 * 
 * database.0.admin_password is not returned by the service for security reasons. Add the following to the resource:
 * 
 *     lifecycle {
 *     
 *         ignore_changes = [&#34;database.0.admin_password&#34;]
 *     
 *     }
 * 
 * The creation of an oci_database_db_system requires that it be created with exactly one oci_database_db_home. Therefore the first db home will have to be a property of the db system resource and any further db homes to be added to the db system will have to be added as first class resources using &#34;oci_database_db_home&#34;.
 * 
 */
@ResourceType(type="oci:Database/dbHome:DbHome")
public class DbHome extends com.pulumi.resources.CustomResource {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Details for creating a database.
     * 
     * **Warning:** Oracle recommends that you avoid using any confidential information when you supply string values using the API.
     * 
     */
    @Export(name="database", refs={DbHomeDatabase.class}, tree="[0]")
    private Output<DbHomeDatabase> database;

    /**
     * @return (Updatable) Details for creating a database.
     * 
     * **Warning:** Oracle recommends that you avoid using any confidential information when you supply string values using the API.
     * 
     */
    public Output<DbHomeDatabase> database() {
        return this.database;
    }
    /**
     * The database software image [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
     * 
     */
    @Export(name="databaseSoftwareImageId", refs={String.class}, tree="[0]")
    private Output<String> databaseSoftwareImageId;

    /**
     * @return The database software image [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
     * 
     */
    public Output<String> databaseSoftwareImageId() {
        return this.databaseSoftwareImageId;
    }
    /**
     * The location of the Oracle Database Home.
     * 
     */
    @Export(name="dbHomeLocation", refs={String.class}, tree="[0]")
    private Output<String> dbHomeLocation;

    /**
     * @return The location of the Oracle Database Home.
     * 
     */
    public Output<String> dbHomeLocation() {
        return this.dbHomeLocation;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system.
     * 
     */
    @Export(name="dbSystemId", refs={String.class}, tree="[0]")
    private Output<String> dbSystemId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system.
     * 
     */
    public Output<String> dbSystemId() {
        return this.dbSystemId;
    }
    /**
     * A valid Oracle Database version. For a list of supported versions, use the ListDbVersions operation.
     * 
     * This cannot be updated in parallel with any of the following: licenseModel, dbEdition, cpuCoreCount, computeCount, computeModel, adminPassword, whitelistedIps, isMTLSConnectionRequired, openMode, permissionLevel, dbWorkload, privateEndpointLabel, nsgIds, isRefreshable, dbName, scheduledOperations, dbToolsDetails, isLocalDataGuardEnabled, or isFreeTier.
     * 
     */
    @Export(name="dbVersion", refs={String.class}, tree="[0]")
    private Output<String> dbVersion;

    /**
     * @return A valid Oracle Database version. For a list of supported versions, use the ListDbVersions operation.
     * 
     * This cannot be updated in parallel with any of the following: licenseModel, dbEdition, cpuCoreCount, computeCount, computeModel, adminPassword, whitelistedIps, isMTLSConnectionRequired, openMode, permissionLevel, dbWorkload, privateEndpointLabel, nsgIds, isRefreshable, dbName, scheduledOperations, dbToolsDetails, isLocalDataGuardEnabled, or isFreeTier.
     * 
     */
    public Output<String> dbVersion() {
        return this.dbVersion;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    @Export(name="definedTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Output<Map<String,String>> definedTags() {
        return this.definedTags;
    }
    /**
     * The user-provided name of the Database Home.
     * 
     */
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    /**
     * @return The user-provided name of the Database Home.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    @Export(name="enableDatabaseDelete", refs={Boolean.class}, tree="[0]")
    private Output</* @Nullable */ Boolean> enableDatabaseDelete;

    public Output<Optional<Boolean>> enableDatabaseDelete() {
        return Codegen.optional(this.enableDatabaseDelete);
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
     * If true, the customer acknowledges that the specified Oracle Database software is an older release that is not currently supported by OCI.
     * 
     */
    @Export(name="isDesupportedVersion", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> isDesupportedVersion;

    /**
     * @return If true, the customer acknowledges that the specified Oracle Database software is an older release that is not currently supported by OCI.
     * 
     */
    public Output<Boolean> isDesupportedVersion() {
        return this.isDesupportedVersion;
    }
    /**
     * Indicates whether unified autiding is enabled or not. Set to True to enable unified auditing on respective DBHome.
     * 
     */
    @Export(name="isUnifiedAuditingEnabled", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> isUnifiedAuditingEnabled;

    /**
     * @return Indicates whether unified autiding is enabled or not. Set to True to enable unified auditing on respective DBHome.
     * 
     */
    public Output<Boolean> isUnifiedAuditingEnabled() {
        return this.isUnifiedAuditingEnabled;
    }
    /**
     * The OCID of the key container that is used as the master encryption key in database transparent data encryption (TDE) operations.
     * 
     */
    @Export(name="kmsKeyId", refs={String.class}, tree="[0]")
    private Output<String> kmsKeyId;

    /**
     * @return The OCID of the key container that is used as the master encryption key in database transparent data encryption (TDE) operations.
     * 
     */
    public Output<String> kmsKeyId() {
        return this.kmsKeyId;
    }
    /**
     * The OCID of the key container version that is used in database transparent data encryption (TDE) operations KMS Key can have multiple key versions. If none is specified, the current key version (latest) of the Key Id is used for the operation.
     * 
     */
    @Export(name="kmsKeyVersionId", refs={String.class}, tree="[0]")
    private Output<String> kmsKeyVersionId;

    /**
     * @return The OCID of the key container version that is used in database transparent data encryption (TDE) operations KMS Key can have multiple key versions. If none is specified, the current key version (latest) of the Key Id is used for the operation.
     * 
     */
    public Output<String> kmsKeyVersionId() {
        return this.kmsKeyVersionId;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last patch history. This value is updated as soon as a patch operation is started.
     * 
     */
    @Export(name="lastPatchHistoryEntryId", refs={String.class}, tree="[0]")
    private Output<String> lastPatchHistoryEntryId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last patch history. This value is updated as soon as a patch operation is started.
     * 
     */
    public Output<String> lastPatchHistoryEntryId() {
        return this.lastPatchHistoryEntryId;
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
     * The source of database: NONE for creating a new database. DB_BACKUP for creating a new database by restoring from a database backup. VM_CLUSTER_NEW for creating a database for VM Cluster.
     * 
     */
    @Export(name="source", refs={String.class}, tree="[0]")
    private Output<String> source;

    /**
     * @return The source of database: NONE for creating a new database. DB_BACKUP for creating a new database by restoring from a database backup. VM_CLUSTER_NEW for creating a database for VM Cluster.
     * 
     */
    public Output<String> source() {
        return this.source;
    }
    /**
     * The current state of the Database Home.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current state of the Database Home.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    @Export(name="systemTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> systemTags;

    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Output<Map<String,String>> systemTags() {
        return this.systemTags;
    }
    /**
     * The date and time the Database Home was created.
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The date and time the Database Home was created.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="vmClusterId", refs={String.class}, tree="[0]")
    private Output<String> vmClusterId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> vmClusterId() {
        return this.vmClusterId;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public DbHome(java.lang.String name) {
        this(name, DbHomeArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public DbHome(java.lang.String name, @Nullable DbHomeArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public DbHome(java.lang.String name, @Nullable DbHomeArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Database/dbHome:DbHome", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private DbHome(java.lang.String name, Output<java.lang.String> id, @Nullable DbHomeState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Database/dbHome:DbHome", name, state, makeResourceOptions(options, id), false);
    }

    private static DbHomeArgs makeArgs(@Nullable DbHomeArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? DbHomeArgs.Empty : args;
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
    public static DbHome get(java.lang.String name, Output<java.lang.String> id, @Nullable DbHomeState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new DbHome(name, id, state, options);
    }
}
