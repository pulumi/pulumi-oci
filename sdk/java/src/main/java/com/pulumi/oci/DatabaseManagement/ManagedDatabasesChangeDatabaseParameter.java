// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.DatabaseManagement.ManagedDatabasesChangeDatabaseParameterArgs;
import com.pulumi.oci.DatabaseManagement.inputs.ManagedDatabasesChangeDatabaseParameterState;
import com.pulumi.oci.DatabaseManagement.outputs.ManagedDatabasesChangeDatabaseParameterCredentials;
import com.pulumi.oci.DatabaseManagement.outputs.ManagedDatabasesChangeDatabaseParameterParameter;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.List;
import javax.annotation.Nullable;

/**
 * This resource provides the Managed Databases Change Database Parameter resource in Oracle Cloud Infrastructure Database Management service.
 * 
 * Changes database parameter values. There are two kinds of database
 * parameters:
 * 
 * - Dynamic parameters: They can be changed for the current Oracle
 *   Database instance. The changes take effect immediately.
 * - Static parameters: They cannot be changed for the current instance.
 *   You must change these parameters and then restart the database before
 *   changes take effect.
 * 
 * **Note:** If the instance is started using a text initialization
 * parameter file, the parameter changes are applicable only for the
 * current instance. You must update them manually to be passed to
 * a future instance.
 * 
 * ## Example Usage
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.DatabaseManagement.ManagedDatabasesChangeDatabaseParameter;
 * import com.pulumi.oci.DatabaseManagement.ManagedDatabasesChangeDatabaseParameterArgs;
 * import com.pulumi.oci.DatabaseManagement.inputs.ManagedDatabasesChangeDatabaseParameterCredentialsArgs;
 * import com.pulumi.oci.DatabaseManagement.inputs.ManagedDatabasesChangeDatabaseParameterParameterArgs;
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
 *         var testManagedDatabasesChangeDatabaseParameter = new ManagedDatabasesChangeDatabaseParameter(&#34;testManagedDatabasesChangeDatabaseParameter&#34;, ManagedDatabasesChangeDatabaseParameterArgs.builder()        
 *             .credentials(ManagedDatabasesChangeDatabaseParameterCredentialsArgs.builder()
 *                 .password(var_.managed_databases_change_database_parameter_credentials_password())
 *                 .role(var_.managed_databases_change_database_parameter_credentials_role())
 *                 .secretId(oci_vault_secret.test_secret().id())
 *                 .userName(oci_identity_user.test_user().name())
 *                 .build())
 *             .managedDatabaseId(oci_database_management_managed_database.test_managed_database().id())
 *             .parameters(ManagedDatabasesChangeDatabaseParameterParameterArgs.builder()
 *                 .name(var_.managed_databases_change_database_parameter_parameters_name())
 *                 .value(var_.managed_databases_change_database_parameter_parameters_value())
 *                 .updateComment(var_.managed_databases_change_database_parameter_parameters_update_comment())
 *                 .build())
 *             .scope(var_.managed_databases_change_database_parameter_scope())
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * Import is not supported for this resource.
 * 
 */
@ResourceType(type="oci:DatabaseManagement/managedDatabasesChangeDatabaseParameter:ManagedDatabasesChangeDatabaseParameter")
public class ManagedDatabasesChangeDatabaseParameter extends com.pulumi.resources.CustomResource {
    /**
     * The database credentials used to perform management activity.
     * 
     */
    @Export(name="credentials", type=ManagedDatabasesChangeDatabaseParameterCredentials.class, parameters={})
    private Output<ManagedDatabasesChangeDatabaseParameterCredentials> credentials;

    /**
     * @return The database credentials used to perform management activity.
     * 
     */
    public Output<ManagedDatabasesChangeDatabaseParameterCredentials> credentials() {
        return this.credentials;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     * 
     */
    @Export(name="managedDatabaseId", type=String.class, parameters={})
    private Output<String> managedDatabaseId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     * 
     */
    public Output<String> managedDatabaseId() {
        return this.managedDatabaseId;
    }
    /**
     * A list of database parameters and their values.
     * 
     */
    @Export(name="parameters", type=List.class, parameters={ManagedDatabasesChangeDatabaseParameterParameter.class})
    private Output<List<ManagedDatabasesChangeDatabaseParameterParameter>> parameters;

    /**
     * @return A list of database parameters and their values.
     * 
     */
    public Output<List<ManagedDatabasesChangeDatabaseParameterParameter>> parameters() {
        return this.parameters;
    }
    /**
     * The clause used to specify when the parameter change takes effect.
     * 
     */
    @Export(name="scope", type=String.class, parameters={})
    private Output<String> scope;

    /**
     * @return The clause used to specify when the parameter change takes effect.
     * 
     */
    public Output<String> scope() {
        return this.scope;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public ManagedDatabasesChangeDatabaseParameter(String name) {
        this(name, ManagedDatabasesChangeDatabaseParameterArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public ManagedDatabasesChangeDatabaseParameter(String name, ManagedDatabasesChangeDatabaseParameterArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public ManagedDatabasesChangeDatabaseParameter(String name, ManagedDatabasesChangeDatabaseParameterArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DatabaseManagement/managedDatabasesChangeDatabaseParameter:ManagedDatabasesChangeDatabaseParameter", name, args == null ? ManagedDatabasesChangeDatabaseParameterArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private ManagedDatabasesChangeDatabaseParameter(String name, Output<String> id, @Nullable ManagedDatabasesChangeDatabaseParameterState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DatabaseManagement/managedDatabasesChangeDatabaseParameter:ManagedDatabasesChangeDatabaseParameter", name, state, makeResourceOptions(options, id));
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
    public static ManagedDatabasesChangeDatabaseParameter get(String name, Output<String> id, @Nullable ManagedDatabasesChangeDatabaseParameterState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new ManagedDatabasesChangeDatabaseParameter(name, id, state, options);
    }
}