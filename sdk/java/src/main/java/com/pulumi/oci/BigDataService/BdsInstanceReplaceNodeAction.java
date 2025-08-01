// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.BigDataService.BdsInstanceReplaceNodeActionArgs;
import com.pulumi.oci.BigDataService.inputs.BdsInstanceReplaceNodeActionState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * This resource replaces the node with the given hostname, in Oracle Cloud Infrastructure Big Data Service cluster.
 * 
 * Replace the node with the given host name in the cluster.
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
 * import com.pulumi.oci.BigDataService.BdsInstanceReplaceNodeAction;
 * import com.pulumi.oci.BigDataService.BdsInstanceReplaceNodeActionArgs;
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
 *         var testBdsInstanceReplaceNodeAction = new BdsInstanceReplaceNodeAction("testBdsInstanceReplaceNodeAction", BdsInstanceReplaceNodeActionArgs.builder()
 *             .bdsInstanceId(testBdsInstance.id())
 *             .nodeHostName(bdsInstanceReplaceNodeAction.nodeHostName())
 *             .nodeBackupId(bdsInstanceReplaceNodeAction.nodeBackupId())
 *             .clusterAdminPassword(testBdsInstance.clusterAdminPassword())
 *             .shape(shape)
 *             .build());
 * 
 *     }
 * }
 * }
 * </pre>
 * &lt;!--End PulumiCodeChooser --&gt;
 * 
 */
@ResourceType(type="oci:BigDataService/bdsInstanceReplaceNodeAction:BdsInstanceReplaceNodeAction")
public class BdsInstanceReplaceNodeAction extends com.pulumi.resources.CustomResource {
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
     * The id of the nodeBackup to use for replacing the node.
     * 
     */
    @Export(name="nodeBackupId", refs={String.class}, tree="[0]")
    private Output<String> nodeBackupId;

    /**
     * @return The id of the nodeBackup to use for replacing the node.
     * 
     */
    public Output<String> nodeBackupId() {
        return this.nodeBackupId;
    }
    /**
     * Host name of the node to replace. MASTER, UTILITY and EDGE node are only supported types
     * 
     */
    @Export(name="nodeHostName", refs={String.class}, tree="[0]")
    private Output<String> nodeHostName;

    /**
     * @return Host name of the node to replace. MASTER, UTILITY and EDGE node are only supported types
     * 
     */
    public Output<String> nodeHostName() {
        return this.nodeHostName;
    }
    /**
     * Shape of the new vm when replacing the node. If not provided, BDS will attempt to replace the node with the shape of current node.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="shape", refs={String.class}, tree="[0]")
    private Output</* @Nullable */ String> shape;

    /**
     * @return Shape of the new vm when replacing the node. If not provided, BDS will attempt to replace the node with the shape of current node.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<Optional<String>> shape() {
        return Codegen.optional(this.shape);
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public BdsInstanceReplaceNodeAction(java.lang.String name) {
        this(name, BdsInstanceReplaceNodeActionArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public BdsInstanceReplaceNodeAction(java.lang.String name, BdsInstanceReplaceNodeActionArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public BdsInstanceReplaceNodeAction(java.lang.String name, BdsInstanceReplaceNodeActionArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:BigDataService/bdsInstanceReplaceNodeAction:BdsInstanceReplaceNodeAction", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private BdsInstanceReplaceNodeAction(java.lang.String name, Output<java.lang.String> id, @Nullable BdsInstanceReplaceNodeActionState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:BigDataService/bdsInstanceReplaceNodeAction:BdsInstanceReplaceNodeAction", name, state, makeResourceOptions(options, id), false);
    }

    private static BdsInstanceReplaceNodeActionArgs makeArgs(BdsInstanceReplaceNodeActionArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? BdsInstanceReplaceNodeActionArgs.Empty : args;
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
    public static BdsInstanceReplaceNodeAction get(java.lang.String name, Output<java.lang.String> id, @Nullable BdsInstanceReplaceNodeActionState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new BdsInstanceReplaceNodeAction(name, id, state, options);
    }
}
