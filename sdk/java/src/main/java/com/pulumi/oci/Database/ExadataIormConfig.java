// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Database.ExadataIormConfigArgs;
import com.pulumi.oci.Database.inputs.ExadataIormConfigState;
import com.pulumi.oci.Database.outputs.ExadataIormConfigDbPlan;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.List;
import javax.annotation.Nullable;

/**
 * This resource provides the Exadata Iorm Config resource in Oracle Cloud Infrastructure Database service.
 * 
 * Updates IORM settings for the specified Exadata DB system.
 * 
 * **Note:** Deprecated for Exadata Cloud Service systems. Use the [new resource model APIs](https://docs.cloud.oracle.com/iaas/Content/Database/Concepts/exaflexsystem.htm#exaflexsystem_topic-resource_model) instead.
 * 
 * For Exadata Cloud Service instances, support for this API will end on May 15th, 2021. See [Switching an Exadata DB System to the New Resource Model and APIs](https://docs.cloud.oracle.com/iaas/Content/Database/Concepts/exaflexsystem_topic-resource_model_conversion.htm) for details on converting existing Exadata DB systems to the new resource model.
 * 
 * The [UpdateCloudVmClusterIormConfig](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/CloudVmCluster/UpdateCloudVmClusterIormConfig/) API is used for Exadata systems using the
 * new resource model.
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
 * import com.pulumi.oci.Database.ExadataIormConfig;
 * import com.pulumi.oci.Database.ExadataIormConfigArgs;
 * import com.pulumi.oci.Database.inputs.ExadataIormConfigDbPlanArgs;
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
 *         var testExadataIormConfig = new ExadataIormConfig("testExadataIormConfig", ExadataIormConfigArgs.builder()
 *             .dbPlans(ExadataIormConfigDbPlanArgs.builder()
 *                 .dbName(exadataIormConfigDbPlansDbName)
 *                 .share(exadataIormConfigDbPlansShare)
 *                 .build())
 *             .dbSystemId(testDbSystem.id())
 *             .objective("AUTO")
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
@ResourceType(type="oci:Database/exadataIormConfig:ExadataIormConfig")
public class ExadataIormConfig extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) Array of IORM Setting for all the database in this Exadata DB System
     * 
     */
    @Export(name="dbPlans", refs={List.class,ExadataIormConfigDbPlan.class}, tree="[0,1]")
    private Output<List<ExadataIormConfigDbPlan>> dbPlans;

    /**
     * @return (Updatable) Array of IORM Setting for all the database in this Exadata DB System
     * 
     */
    public Output<List<ExadataIormConfigDbPlan>> dbPlans() {
        return this.dbPlans;
    }
    /**
     * (Updatable) The DB system [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Export(name="dbSystemId", refs={String.class}, tree="[0]")
    private Output<String> dbSystemId;

    /**
     * @return (Updatable) The DB system [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Output<String> dbSystemId() {
        return this.dbSystemId;
    }
    /**
     * Additional information about the current `lifecycleState`.
     * 
     */
    @Export(name="lifecycleDetails", refs={String.class}, tree="[0]")
    private Output<String> lifecycleDetails;

    /**
     * @return Additional information about the current `lifecycleState`.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * (Updatable) Value for the IORM objective Default is &#34;Auto&#34;
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="objective", refs={String.class}, tree="[0]")
    private Output<String> objective;

    /**
     * @return (Updatable) Value for the IORM objective Default is &#34;Auto&#34;
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> objective() {
        return this.objective;
    }
    /**
     * The current state of IORM configuration for the Exadata DB system.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current state of IORM configuration for the Exadata DB system.
     * 
     */
    public Output<String> state() {
        return this.state;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public ExadataIormConfig(java.lang.String name) {
        this(name, ExadataIormConfigArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public ExadataIormConfig(java.lang.String name, ExadataIormConfigArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public ExadataIormConfig(java.lang.String name, ExadataIormConfigArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Database/exadataIormConfig:ExadataIormConfig", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private ExadataIormConfig(java.lang.String name, Output<java.lang.String> id, @Nullable ExadataIormConfigState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Database/exadataIormConfig:ExadataIormConfig", name, state, makeResourceOptions(options, id), false);
    }

    private static ExadataIormConfigArgs makeArgs(ExadataIormConfigArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? ExadataIormConfigArgs.Empty : args;
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
    public static ExadataIormConfig get(java.lang.String name, Output<java.lang.String> id, @Nullable ExadataIormConfigState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new ExadataIormConfig(name, id, state, options);
    }
}
