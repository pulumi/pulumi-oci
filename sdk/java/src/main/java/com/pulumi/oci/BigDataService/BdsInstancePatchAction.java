// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.BigDataService.BdsInstancePatchActionArgs;
import com.pulumi.oci.BigDataService.inputs.BdsInstancePatchActionState;
import com.pulumi.oci.BigDataService.outputs.BdsInstancePatchActionPatchingConfig;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.List;
import javax.annotation.Nullable;

/**
 * This resource provides the Bds Instance Patch Action resource in Oracle Cloud Infrastructure Big Data Service service.
 * 
 * Install the specified patch to this cluster.
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
 * import com.pulumi.oci.BigDataService.BdsInstancePatchAction;
 * import com.pulumi.oci.BigDataService.BdsInstancePatchActionArgs;
 * import com.pulumi.oci.BigDataService.inputs.BdsInstancePatchActionPatchingConfigArgs;
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
 *         var testBdsInstancePatchAction = new BdsInstancePatchAction("testBdsInstancePatchAction", BdsInstancePatchActionArgs.builder()
 *             .bdsInstanceId(testBdsInstance.id())
 *             .clusterAdminPassword(bdsInstancePatchActionClusterAdminPassword)
 *             .version(bdsInstancePatchActionVersion)
 *             .patchingConfig(BdsInstancePatchActionPatchingConfigArgs.builder()
 *                 .patchingConfigStrategy(bdsInstancePatchActionPatchingConfigPatchingConfigStrategy)
 *                 .batchSize(bdsInstancePatchActionPatchingConfigBatchSize)
 *                 .toleranceThresholdPerBatch(bdsInstancePatchActionPatchingConfigToleranceThresholdPerBatch)
 *                 .toleranceThresholdPerDomain(bdsInstancePatchActionPatchingConfigToleranceThresholdPerDomain)
 *                 .waitTimeBetweenBatchInSeconds(bdsInstancePatchActionPatchingConfigWaitTimeBetweenBatchInSeconds)
 *                 .waitTimeBetweenDomainInSeconds(bdsInstancePatchActionPatchingConfigWaitTimeBetweenDomainInSeconds)
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
 * Import is not supported for this resource.
 * 
 */
@ResourceType(type="oci:BigDataService/bdsInstancePatchAction:BdsInstancePatchAction")
public class BdsInstancePatchAction extends com.pulumi.resources.CustomResource {
    /**
     * The OCID of the cluster.
     * 
     */
    @Export(name="bdsInstanceId", refs={String.class}, tree="[0]")
    private Output<String> bdsInstanceId;

    /**
     * @return The OCID of the cluster.
     * 
     */
    public Output<String> bdsInstanceId() {
        return this.bdsInstanceId;
    }
    /**
     * Base-64 encoded password for the cluster admin user.
     * 
     */
    @Export(name="clusterAdminPassword", refs={String.class}, tree="[0]")
    private Output<String> clusterAdminPassword;

    /**
     * @return Base-64 encoded password for the cluster admin user.
     * 
     */
    public Output<String> clusterAdminPassword() {
        return this.clusterAdminPassword;
    }
    /**
     * Detailed configurations for defining the behavior when installing ODH patches. If not provided, nodes will be patched with down time.
     * 
     */
    @Export(name="patchingConfig", refs={BdsInstancePatchActionPatchingConfig.class}, tree="[0]")
    private Output<BdsInstancePatchActionPatchingConfig> patchingConfig;

    /**
     * @return Detailed configurations for defining the behavior when installing ODH patches. If not provided, nodes will be patched with down time.
     * 
     */
    public Output<BdsInstancePatchActionPatchingConfig> patchingConfig() {
        return this.patchingConfig;
    }
    /**
     * The version of the patch to be installed.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="version", refs={String.class}, tree="[0]")
    private Output<String> version;

    /**
     * @return The version of the patch to be installed.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> version() {
        return this.version;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public BdsInstancePatchAction(java.lang.String name) {
        this(name, BdsInstancePatchActionArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public BdsInstancePatchAction(java.lang.String name, BdsInstancePatchActionArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public BdsInstancePatchAction(java.lang.String name, BdsInstancePatchActionArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:BigDataService/bdsInstancePatchAction:BdsInstancePatchAction", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private BdsInstancePatchAction(java.lang.String name, Output<java.lang.String> id, @Nullable BdsInstancePatchActionState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:BigDataService/bdsInstancePatchAction:BdsInstancePatchAction", name, state, makeResourceOptions(options, id), false);
    }

    private static BdsInstancePatchActionArgs makeArgs(BdsInstancePatchActionArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? BdsInstancePatchActionArgs.Empty : args;
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<java.lang.String> id) {
        var defaultOptions = com.pulumi.resources.CustomResourceOptions.builder()
            .version(Utilities.getVersion())
            .additionalSecretOutputs(List.of(
                "clusterAdminPassword"
            ))
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
    public static BdsInstancePatchAction get(java.lang.String name, Output<java.lang.String> id, @Nullable BdsInstancePatchActionState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new BdsInstancePatchAction(name, id, state, options);
    }
}
