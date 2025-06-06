// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.DatabaseManagement.ExternalMySqlDatabaseArgs;
import com.pulumi.oci.DatabaseManagement.inputs.ExternalMySqlDatabaseState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import javax.annotation.Nullable;

/**
 * This resource provides the External My Sql Database resource in Oracle Cloud Infrastructure Database Management service.
 * 
 * Creates an external MySQL database.
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
 * import com.pulumi.oci.DatabaseManagement.ExternalMySqlDatabase;
 * import com.pulumi.oci.DatabaseManagement.ExternalMySqlDatabaseArgs;
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
 *         var testExternalMySqlDatabase = new ExternalMySqlDatabase("testExternalMySqlDatabase", ExternalMySqlDatabaseArgs.builder()
 *             .compartmentId(compartmentId)
 *             .dbName(externalMySqlDatabaseDbName)
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
 * ExternalMySqlDatabases can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:DatabaseManagement/externalMySqlDatabase:ExternalMySqlDatabase test_external_my_sql_database &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:DatabaseManagement/externalMySqlDatabase:ExternalMySqlDatabase")
public class ExternalMySqlDatabase extends com.pulumi.resources.CustomResource {
    /**
     * OCID of compartment for the External MySQL Database.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return OCID of compartment for the External MySQL Database.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Name of the External MySQL Database.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="dbName", refs={String.class}, tree="[0]")
    private Output<String> dbName;

    /**
     * @return (Updatable) Name of the External MySQL Database.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> dbName() {
        return this.dbName;
    }
    /**
     * OCID of External MySQL Database.
     * 
     */
    @Export(name="externalDatabaseId", refs={String.class}, tree="[0]")
    private Output<String> externalDatabaseId;

    /**
     * @return OCID of External MySQL Database.
     * 
     */
    public Output<String> externalDatabaseId() {
        return this.externalDatabaseId;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public ExternalMySqlDatabase(java.lang.String name) {
        this(name, ExternalMySqlDatabaseArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public ExternalMySqlDatabase(java.lang.String name, ExternalMySqlDatabaseArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public ExternalMySqlDatabase(java.lang.String name, ExternalMySqlDatabaseArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DatabaseManagement/externalMySqlDatabase:ExternalMySqlDatabase", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private ExternalMySqlDatabase(java.lang.String name, Output<java.lang.String> id, @Nullable ExternalMySqlDatabaseState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DatabaseManagement/externalMySqlDatabase:ExternalMySqlDatabase", name, state, makeResourceOptions(options, id), false);
    }

    private static ExternalMySqlDatabaseArgs makeArgs(ExternalMySqlDatabaseArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? ExternalMySqlDatabaseArgs.Empty : args;
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
    public static ExternalMySqlDatabase get(java.lang.String name, Output<java.lang.String> id, @Nullable ExternalMySqlDatabaseState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new ExternalMySqlDatabase(name, id, state, options);
    }
}
