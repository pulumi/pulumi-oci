// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.DatabaseManagement.ManagedDatabaseGroupArgs;
import com.pulumi.oci.DatabaseManagement.inputs.ManagedDatabaseGroupState;
import com.pulumi.oci.DatabaseManagement.outputs.ManagedDatabaseGroupManagedDatabase;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.List;
import javax.annotation.Nullable;

/**
 * This resource provides the Managed Database Group resource in Oracle Cloud Infrastructure Database Management service.
 * 
 * Creates a Managed Database Group. The group does not contain any
 * Managed Databases when it is created, and they must be added later.
 * 
 * ## Example Usage
 * 
 * ## Import
 * 
 * ManagedDatabaseGroups can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:DatabaseManagement/managedDatabaseGroup:ManagedDatabaseGroup test_managed_database_group &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:DatabaseManagement/managedDatabaseGroup:ManagedDatabaseGroup")
public class ManagedDatabaseGroup extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the Managed Database Group resides.
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the Managed Database Group resides.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) The information specified by the user about the Managed Database Group.
     * 
     */
    @Export(name="description", type=String.class, parameters={})
    private Output<String> description;

    /**
     * @return (Updatable) The information specified by the user about the Managed Database Group.
     * 
     */
    public Output<String> description() {
        return this.description;
    }
    /**
     * (Updatable) Set of Managed Databases that the user wants to add to the Managed Database Group. Specifying a block will add the Managed Database to Managed Database Group and removing the block will remove Managed Database from the Managed Database Group.
     * 
     */
    @Export(name="managedDatabases", type=List.class, parameters={ManagedDatabaseGroupManagedDatabase.class})
    private Output<List<ManagedDatabaseGroupManagedDatabase>> managedDatabases;

    /**
     * @return (Updatable) Set of Managed Databases that the user wants to add to the Managed Database Group. Specifying a block will add the Managed Database to Managed Database Group and removing the block will remove Managed Database from the Managed Database Group.
     * 
     */
    public Output<List<ManagedDatabaseGroupManagedDatabase>> managedDatabases() {
        return this.managedDatabases;
    }
    /**
     * The name of the Managed Database Group. Valid characters are uppercase or lowercase letters, numbers, and &#34;_&#34;. The name of the Managed Database Group cannot be modified. It must be unique in the compartment and must begin with an alphabetic character.
     * 
     */
    @Export(name="name", type=String.class, parameters={})
    private Output<String> name;

    /**
     * @return The name of the Managed Database Group. Valid characters are uppercase or lowercase letters, numbers, and &#34;_&#34;. The name of the Managed Database Group cannot be modified. It must be unique in the compartment and must begin with an alphabetic character.
     * 
     */
    public Output<String> name() {
        return this.name;
    }
    /**
     * The current lifecycle state of the Managed Database Group.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current lifecycle state of the Managed Database Group.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The date and time the Managed Database Group was created.
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The date and time the Managed Database Group was created.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The date and time the Managed Database Group was last updated.
     * 
     */
    @Export(name="timeUpdated", type=String.class, parameters={})
    private Output<String> timeUpdated;

    /**
     * @return The date and time the Managed Database Group was last updated.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public ManagedDatabaseGroup(String name) {
        this(name, ManagedDatabaseGroupArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public ManagedDatabaseGroup(String name, ManagedDatabaseGroupArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public ManagedDatabaseGroup(String name, ManagedDatabaseGroupArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DatabaseManagement/managedDatabaseGroup:ManagedDatabaseGroup", name, args == null ? ManagedDatabaseGroupArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private ManagedDatabaseGroup(String name, Output<String> id, @Nullable ManagedDatabaseGroupState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DatabaseManagement/managedDatabaseGroup:ManagedDatabaseGroup", name, state, makeResourceOptions(options, id));
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
    public static ManagedDatabaseGroup get(String name, Output<String> id, @Nullable ManagedDatabaseGroupState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new ManagedDatabaseGroup(name, id, state, options);
    }
}
