// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FusionApps;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.FusionApps.FusionEnvironmentRefreshActivityArgs;
import com.pulumi.oci.FusionApps.inputs.FusionEnvironmentRefreshActivityState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import javax.annotation.Nullable;

/**
 * This resource provides the Fusion Environment Refresh Activity resource in Oracle Cloud Infrastructure Fusion Apps service.
 * 
 * Creates a new RefreshActivity.
 * 
 * ## Example Usage
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.FusionApps.FusionEnvironmentRefreshActivity;
 * import com.pulumi.oci.FusionApps.FusionEnvironmentRefreshActivityArgs;
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
 *         var testFusionEnvironmentRefreshActivity = new FusionEnvironmentRefreshActivity(&#34;testFusionEnvironmentRefreshActivity&#34;, FusionEnvironmentRefreshActivityArgs.builder()        
 *             .fusionEnvironmentId(oci_fusion_apps_fusion_environment.test_fusion_environment().id())
 *             .sourceFusionEnvironmentId(oci_fusion_apps_fusion_environment.test_fusion_environment().id())
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * FusionEnvironmentRefreshActivities can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:FusionApps/fusionEnvironmentRefreshActivity:FusionEnvironmentRefreshActivity test_fusion_environment_refresh_activity &#34;fusionEnvironments/{fusionEnvironmentId}/refreshActivities/{refreshActivityId}&#34;
 * ```
 * 
 */
@ResourceType(type="oci:FusionApps/fusionEnvironmentRefreshActivity:FusionEnvironmentRefreshActivity")
public class FusionEnvironmentRefreshActivity extends com.pulumi.resources.CustomResource {
    /**
     * A friendly name for the refresh activity. Can be changed later.
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return A friendly name for the refresh activity. Can be changed later.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * unique FusionEnvironment identifier
     * 
     */
    @Export(name="fusionEnvironmentId", type=String.class, parameters={})
    private Output<String> fusionEnvironmentId;

    /**
     * @return unique FusionEnvironment identifier
     * 
     */
    public Output<String> fusionEnvironmentId() {
        return this.fusionEnvironmentId;
    }
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    @Export(name="lifecycleDetails", type=String.class, parameters={})
    private Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * Service availability / impact during refresh activity execution up down
     * 
     */
    @Export(name="serviceAvailability", type=String.class, parameters={})
    private Output<String> serviceAvailability;

    /**
     * @return Service availability / impact during refresh activity execution up down
     * 
     */
    public Output<String> serviceAvailability() {
        return this.serviceAvailability;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the source environment
     * 
     */
    @Export(name="sourceFusionEnvironmentId", type=String.class, parameters={})
    private Output<String> sourceFusionEnvironmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the source environment
     * 
     */
    public Output<String> sourceFusionEnvironmentId() {
        return this.sourceFusionEnvironmentId;
    }
    /**
     * The current state of the refreshActivity.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current state of the refreshActivity.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The time the refresh activity record was created. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeAccepted", type=String.class, parameters={})
    private Output<String> timeAccepted;

    /**
     * @return The time the refresh activity record was created. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeAccepted() {
        return this.timeAccepted;
    }
    /**
     * The time the refresh activity is scheduled to end. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeExpectedFinish", type=String.class, parameters={})
    private Output<String> timeExpectedFinish;

    /**
     * @return The time the refresh activity is scheduled to end. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeExpectedFinish() {
        return this.timeExpectedFinish;
    }
    /**
     * The time the refresh activity actually completed / cancelled / failed. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeFinished", type=String.class, parameters={})
    private Output<String> timeFinished;

    /**
     * @return The time the refresh activity actually completed / cancelled / failed. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeFinished() {
        return this.timeFinished;
    }
    /**
     * The date and time of the most recent source environment backup used for the environment refresh.
     * 
     */
    @Export(name="timeOfRestorationPoint", type=String.class, parameters={})
    private Output<String> timeOfRestorationPoint;

    /**
     * @return The date and time of the most recent source environment backup used for the environment refresh.
     * 
     */
    public Output<String> timeOfRestorationPoint() {
        return this.timeOfRestorationPoint;
    }
    /**
     * The time the refresh activity is scheduled to start. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeScheduledStart", type=String.class, parameters={})
    private Output<String> timeScheduledStart;

    /**
     * @return The time the refresh activity is scheduled to start. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeScheduledStart() {
        return this.timeScheduledStart;
    }
    /**
     * The time the refresh activity record was updated. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeUpdated", type=String.class, parameters={})
    private Output<String> timeUpdated;

    /**
     * @return The time the refresh activity record was updated. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public FusionEnvironmentRefreshActivity(String name) {
        this(name, FusionEnvironmentRefreshActivityArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public FusionEnvironmentRefreshActivity(String name, FusionEnvironmentRefreshActivityArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public FusionEnvironmentRefreshActivity(String name, FusionEnvironmentRefreshActivityArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:FusionApps/fusionEnvironmentRefreshActivity:FusionEnvironmentRefreshActivity", name, args == null ? FusionEnvironmentRefreshActivityArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private FusionEnvironmentRefreshActivity(String name, Output<String> id, @Nullable FusionEnvironmentRefreshActivityState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:FusionApps/fusionEnvironmentRefreshActivity:FusionEnvironmentRefreshActivity", name, state, makeResourceOptions(options, id));
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
    public static FusionEnvironmentRefreshActivity get(String name, Output<String> id, @Nullable FusionEnvironmentRefreshActivityState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new FusionEnvironmentRefreshActivity(name, id, state, options);
    }
}