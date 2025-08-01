// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.BigDataService.BdsInstanceNodeReplaceConfigurationArgs;
import com.pulumi.oci.BigDataService.inputs.BdsInstanceNodeReplaceConfigurationState;
import com.pulumi.oci.BigDataService.outputs.BdsInstanceNodeReplaceConfigurationLevelTypeDetails;
import com.pulumi.oci.Utilities;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import javax.annotation.Nullable;

/**
 * This resource provides the Bds Instance Node Replace Configuration resource in Oracle Cloud Infrastructure Big Data Service service.
 * 
 * Add a nodeReplaceConfigurations to the cluster.
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
 * import com.pulumi.oci.BigDataService.BdsInstanceNodeReplaceConfiguration;
 * import com.pulumi.oci.BigDataService.BdsInstanceNodeReplaceConfigurationArgs;
 * import com.pulumi.oci.BigDataService.inputs.BdsInstanceNodeReplaceConfigurationLevelTypeDetailsArgs;
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
 *         var testBdsInstanceNodeReplaceConfiguration = new BdsInstanceNodeReplaceConfiguration("testBdsInstanceNodeReplaceConfiguration", BdsInstanceNodeReplaceConfigurationArgs.builder()
 *             .bdsInstanceId(testBdsInstance.id())
 *             .clusterAdminPassword(bdsInstanceNodeReplaceConfigurationClusterAdminPassword)
 *             .durationInMinutes(bdsInstanceNodeReplaceConfigurationDurationInMinutes)
 *             .levelTypeDetails(BdsInstanceNodeReplaceConfigurationLevelTypeDetailsArgs.builder()
 *                 .levelType(bdsInstanceNodeReplaceConfigurationLevelTypeDetailsLevelType)
 *                 .nodeHostName(bdsInstanceNodeReplaceConfigurationLevelTypeDetailsNodeHostName)
 *                 .nodeType(bdsInstanceNodeReplaceConfigurationLevelTypeDetailsNodeType)
 *                 .build())
 *             .metricType(bdsInstanceNodeReplaceConfigurationMetricType)
 *             .displayName(bdsInstanceNodeReplaceConfigurationDisplayName)
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
 * BdsInstanceNodeReplaceConfigurations can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:BigDataService/bdsInstanceNodeReplaceConfiguration:BdsInstanceNodeReplaceConfiguration test_bds_instance_node_replace_configuration &#34;bdsInstances/{bdsInstanceId}/nodeReplaceConfigurations/{nodeReplaceConfigurationId}&#34;
 * ```
 * 
 */
@ResourceType(type="oci:BigDataService/bdsInstanceNodeReplaceConfiguration:BdsInstanceNodeReplaceConfiguration")
public class BdsInstanceNodeReplaceConfiguration extends com.pulumi.resources.CustomResource {
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
     * (Updatable) A user-friendly name. Only ASCII alphanumeric characters with no spaces allowed. The name does not have to be unique, and it may be changed. Avoid entering confidential information.
     * 
     */
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name. Only ASCII alphanumeric characters with no spaces allowed. The name does not have to be unique, and it may be changed. Avoid entering confidential information.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * (Updatable) This value is the minimum period of time to wait before triggering node replacement. The value is in minutes.
     * 
     */
    @Export(name="durationInMinutes", refs={Integer.class}, tree="[0]")
    private Output<Integer> durationInMinutes;

    /**
     * @return (Updatable) This value is the minimum period of time to wait before triggering node replacement. The value is in minutes.
     * 
     */
    public Output<Integer> durationInMinutes() {
        return this.durationInMinutes;
    }
    /**
     * (Updatable) Details of the type of level used to trigger the creation of a new node backup configuration or node replacement configuration.
     * 
     */
    @Export(name="levelTypeDetails", refs={BdsInstanceNodeReplaceConfigurationLevelTypeDetails.class}, tree="[0]")
    private Output<BdsInstanceNodeReplaceConfigurationLevelTypeDetails> levelTypeDetails;

    /**
     * @return (Updatable) Details of the type of level used to trigger the creation of a new node backup configuration or node replacement configuration.
     * 
     */
    public Output<BdsInstanceNodeReplaceConfigurationLevelTypeDetails> levelTypeDetails() {
        return this.levelTypeDetails;
    }
    /**
     * (Updatable) Type of compute instance health metric to use for node replacement
     * 
     */
    @Export(name="metricType", refs={String.class}, tree="[0]")
    private Output<String> metricType;

    /**
     * @return (Updatable) Type of compute instance health metric to use for node replacement
     * 
     */
    public Output<String> metricType() {
        return this.metricType;
    }
    /**
     * The state of the NodeReplaceConfiguration.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The state of the NodeReplaceConfiguration.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The time the NodeReplaceConfiguration was created, shown as an RFC 3339 formatted datetime string.
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The time the NodeReplaceConfiguration was created, shown as an RFC 3339 formatted datetime string.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time the NodeReplaceConfiguration was updated, shown as an RFC 3339 formatted datetime string.
     * 
     */
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    /**
     * @return The time the NodeReplaceConfiguration was updated, shown as an RFC 3339 formatted datetime string.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public BdsInstanceNodeReplaceConfiguration(java.lang.String name) {
        this(name, BdsInstanceNodeReplaceConfigurationArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public BdsInstanceNodeReplaceConfiguration(java.lang.String name, BdsInstanceNodeReplaceConfigurationArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public BdsInstanceNodeReplaceConfiguration(java.lang.String name, BdsInstanceNodeReplaceConfigurationArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:BigDataService/bdsInstanceNodeReplaceConfiguration:BdsInstanceNodeReplaceConfiguration", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private BdsInstanceNodeReplaceConfiguration(java.lang.String name, Output<java.lang.String> id, @Nullable BdsInstanceNodeReplaceConfigurationState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:BigDataService/bdsInstanceNodeReplaceConfiguration:BdsInstanceNodeReplaceConfiguration", name, state, makeResourceOptions(options, id), false);
    }

    private static BdsInstanceNodeReplaceConfigurationArgs makeArgs(BdsInstanceNodeReplaceConfigurationArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? BdsInstanceNodeReplaceConfigurationArgs.Empty : args;
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
    public static BdsInstanceNodeReplaceConfiguration get(java.lang.String name, Output<java.lang.String> id, @Nullable BdsInstanceNodeReplaceConfigurationState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new BdsInstanceNodeReplaceConfiguration(name, id, state, options);
    }
}
