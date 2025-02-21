// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudMigrations;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.CloudMigrations.TargetAssetArgs;
import com.pulumi.oci.CloudMigrations.inputs.TargetAssetState;
import com.pulumi.oci.CloudMigrations.outputs.TargetAssetCompatibilityMessage;
import com.pulumi.oci.CloudMigrations.outputs.TargetAssetEstimatedCost;
import com.pulumi.oci.CloudMigrations.outputs.TargetAssetMigrationAsset;
import com.pulumi.oci.CloudMigrations.outputs.TargetAssetRecommendedSpec;
import com.pulumi.oci.CloudMigrations.outputs.TargetAssetTestSpec;
import com.pulumi.oci.CloudMigrations.outputs.TargetAssetUserSpec;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import javax.annotation.Nullable;

/**
 * This resource provides the Target Asset resource in Oracle Cloud Infrastructure Cloud Migrations service.
 * 
 * Creates a target asset.
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
 * import com.pulumi.oci.CloudMigrations.TargetAsset;
 * import com.pulumi.oci.CloudMigrations.TargetAssetArgs;
 * import com.pulumi.oci.CloudMigrations.inputs.TargetAssetUserSpecArgs;
 * import com.pulumi.oci.CloudMigrations.inputs.TargetAssetUserSpecAgentConfigArgs;
 * import com.pulumi.oci.CloudMigrations.inputs.TargetAssetUserSpecCreateVnicDetailsArgs;
 * import com.pulumi.oci.CloudMigrations.inputs.TargetAssetUserSpecInstanceOptionsArgs;
 * import com.pulumi.oci.CloudMigrations.inputs.TargetAssetUserSpecPreemptibleInstanceConfigArgs;
 * import com.pulumi.oci.CloudMigrations.inputs.TargetAssetUserSpecPreemptibleInstanceConfigPreemptionActionArgs;
 * import com.pulumi.oci.CloudMigrations.inputs.TargetAssetUserSpecShapeConfigArgs;
 * import com.pulumi.oci.CloudMigrations.inputs.TargetAssetUserSpecSourceDetailsArgs;
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
 *         var testTargetAsset = new TargetAsset("testTargetAsset", TargetAssetArgs.builder()
 *             .isExcludedFromExecution(targetAssetIsExcludedFromExecution)
 *             .migrationPlanId(testMigrationPlan.id())
 *             .preferredShapeType(targetAssetPreferredShapeType)
 *             .type(targetAssetType)
 *             .userSpec(TargetAssetUserSpecArgs.builder()
 *                 .agentConfig(TargetAssetUserSpecAgentConfigArgs.builder()
 *                     .areAllPluginsDisabled(targetAssetUserSpecAgentConfigAreAllPluginsDisabled)
 *                     .isManagementDisabled(targetAssetUserSpecAgentConfigIsManagementDisabled)
 *                     .isMonitoringDisabled(targetAssetUserSpecAgentConfigIsMonitoringDisabled)
 *                     .pluginsConfigs(TargetAssetUserSpecAgentConfigPluginsConfigArgs.builder()
 *                         .desiredState(targetAssetUserSpecAgentConfigPluginsConfigDesiredState)
 *                         .name(targetAssetUserSpecAgentConfigPluginsConfigName)
 *                         .build())
 *                     .build())
 *                 .availabilityDomain(targetAssetUserSpecAvailabilityDomain)
 *                 .capacityReservationId(testCapacityReservation.id())
 *                 .compartmentId(compartmentId)
 *                 .createVnicDetails(TargetAssetUserSpecCreateVnicDetailsArgs.builder()
 *                     .assignPrivateDnsRecord(targetAssetUserSpecCreateVnicDetailsAssignPrivateDnsRecord)
 *                     .assignPublicIp(targetAssetUserSpecCreateVnicDetailsAssignPublicIp)
 *                     .definedTags(Map.of("foo-namespace.bar-key", "value"))
 *                     .displayName(targetAssetUserSpecCreateVnicDetailsDisplayName)
 *                     .freeformTags(Map.of("bar-key", "value"))
 *                     .hostnameLabel(targetAssetUserSpecCreateVnicDetailsHostnameLabel)
 *                     .nsgIds(targetAssetUserSpecCreateVnicDetailsNsgIds)
 *                     .privateIp(targetAssetUserSpecCreateVnicDetailsPrivateIp)
 *                     .skipSourceDestCheck(targetAssetUserSpecCreateVnicDetailsSkipSourceDestCheck)
 *                     .subnetId(testSubnet.id())
 *                     .vlanId(testVlan.id())
 *                     .build())
 *                 .dedicatedVmHostId(testDedicatedVmHost.id())
 *                 .definedTags(Map.of("foo-namespace.bar-key", "value"))
 *                 .displayName(targetAssetUserSpecDisplayName)
 *                 .faultDomain(targetAssetUserSpecFaultDomain)
 *                 .freeformTags(Map.of("bar-key", "value"))
 *                 .hostnameLabel(targetAssetUserSpecHostnameLabel)
 *                 .instanceOptions(TargetAssetUserSpecInstanceOptionsArgs.builder()
 *                     .areLegacyImdsEndpointsDisabled(targetAssetUserSpecInstanceOptionsAreLegacyImdsEndpointsDisabled)
 *                     .build())
 *                 .ipxeScript(targetAssetUserSpecIpxeScript)
 *                 .isPvEncryptionInTransitEnabled(targetAssetUserSpecIsPvEncryptionInTransitEnabled)
 *                 .preemptibleInstanceConfig(TargetAssetUserSpecPreemptibleInstanceConfigArgs.builder()
 *                     .preemptionAction(TargetAssetUserSpecPreemptibleInstanceConfigPreemptionActionArgs.builder()
 *                         .type(targetAssetUserSpecPreemptibleInstanceConfigPreemptionActionType)
 *                         .preserveBootVolume(targetAssetUserSpecPreemptibleInstanceConfigPreemptionActionPreserveBootVolume)
 *                         .build())
 *                     .build())
 *                 .shape(targetAssetUserSpecShape)
 *                 .shapeConfig(TargetAssetUserSpecShapeConfigArgs.builder()
 *                     .baselineOcpuUtilization(targetAssetUserSpecShapeConfigBaselineOcpuUtilization)
 *                     .memoryInGbs(targetAssetUserSpecShapeConfigMemoryInGbs)
 *                     .ocpus(targetAssetUserSpecShapeConfigOcpus)
 *                     .build())
 *                 .sourceDetails(TargetAssetUserSpecSourceDetailsArgs.builder()
 *                     .sourceType(targetAssetUserSpecSourceDetailsSourceType)
 *                     .bootVolumeId(testBootVolume.id())
 *                     .bootVolumeSizeInGbs(targetAssetUserSpecSourceDetailsBootVolumeSizeInGbs)
 *                     .bootVolumeVpusPerGb(targetAssetUserSpecSourceDetailsBootVolumeVpusPerGb)
 *                     .imageId(testImage.id())
 *                     .kmsKeyId(testKey.id())
 *                     .build())
 *                 .build())
 *             .blockVolumesPerformance(targetAssetBlockVolumesPerformance)
 *             .msLicense(targetAssetMsLicense)
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
 * TargetAssets can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:CloudMigrations/targetAsset:TargetAsset test_target_asset &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:CloudMigrations/targetAsset:TargetAsset")
public class TargetAsset extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) Performance of the block volumes.
     * 
     */
    @Export(name="blockVolumesPerformance", refs={Integer.class}, tree="[0]")
    private Output<Integer> blockVolumesPerformance;

    /**
     * @return (Updatable) Performance of the block volumes.
     * 
     */
    public Output<Integer> blockVolumesPerformance() {
        return this.blockVolumesPerformance;
    }
    /**
     * The OCID of the compartment.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return The OCID of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * Messages about the compatibility issues.
     * 
     */
    @Export(name="compatibilityMessages", refs={List.class,TargetAssetCompatibilityMessage.class}, tree="[0,1]")
    private Output<List<TargetAssetCompatibilityMessage>> compatibilityMessages;

    /**
     * @return Messages about the compatibility issues.
     * 
     */
    public Output<List<TargetAssetCompatibilityMessage>> compatibilityMessages() {
        return this.compatibilityMessages;
    }
    /**
     * Created resource identifier
     * 
     */
    @Export(name="createdResourceId", refs={String.class}, tree="[0]")
    private Output<String> createdResourceId;

    /**
     * @return Created resource identifier
     * 
     */
    public Output<String> createdResourceId() {
        return this.createdResourceId;
    }
    /**
     * A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * Cost estimation description
     * 
     */
    @Export(name="estimatedCosts", refs={List.class,TargetAssetEstimatedCost.class}, tree="[0,1]")
    private Output<List<TargetAssetEstimatedCost>> estimatedCosts;

    /**
     * @return Cost estimation description
     * 
     */
    public Output<List<TargetAssetEstimatedCost>> estimatedCosts() {
        return this.estimatedCosts;
    }
    /**
     * (Updatable) A boolean indicating whether the asset should be migrated.
     * 
     */
    @Export(name="isExcludedFromExecution", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> isExcludedFromExecution;

    /**
     * @return (Updatable) A boolean indicating whether the asset should be migrated.
     * 
     */
    public Output<Boolean> isExcludedFromExecution() {
        return this.isExcludedFromExecution;
    }
    /**
     * A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
     * 
     */
    @Export(name="lifecycleDetails", refs={String.class}, tree="[0]")
    private Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * Description of the migration asset.
     * 
     */
    @Export(name="migrationAssets", refs={List.class,TargetAssetMigrationAsset.class}, tree="[0,1]")
    private Output<List<TargetAssetMigrationAsset>> migrationAssets;

    /**
     * @return Description of the migration asset.
     * 
     */
    public Output<List<TargetAssetMigrationAsset>> migrationAssets() {
        return this.migrationAssets;
    }
    /**
     * OCID of the associated migration plan.
     * 
     */
    @Export(name="migrationPlanId", refs={String.class}, tree="[0]")
    private Output<String> migrationPlanId;

    /**
     * @return OCID of the associated migration plan.
     * 
     */
    public Output<String> migrationPlanId() {
        return this.migrationPlanId;
    }
    /**
     * (Updatable) Microsoft license for the VM configuration.
     * 
     */
    @Export(name="msLicense", refs={String.class}, tree="[0]")
    private Output<String> msLicense;

    /**
     * @return (Updatable) Microsoft license for the VM configuration.
     * 
     */
    public Output<String> msLicense() {
        return this.msLicense;
    }
    /**
     * (Updatable) Preferred VM shape type that you provide.
     * 
     */
    @Export(name="preferredShapeType", refs={String.class}, tree="[0]")
    private Output<String> preferredShapeType;

    /**
     * @return (Updatable) Preferred VM shape type that you provide.
     * 
     */
    public Output<String> preferredShapeType() {
        return this.preferredShapeType;
    }
    /**
     * Instance launch details. Use the `sourceDetails` parameter to specify whether a boot volume or an image should be used to launch a new instance.
     * 
     */
    @Export(name="recommendedSpecs", refs={List.class,TargetAssetRecommendedSpec.class}, tree="[0,1]")
    private Output<List<TargetAssetRecommendedSpec>> recommendedSpecs;

    /**
     * @return Instance launch details. Use the `sourceDetails` parameter to specify whether a boot volume or an image should be used to launch a new instance.
     * 
     */
    public Output<List<TargetAssetRecommendedSpec>> recommendedSpecs() {
        return this.recommendedSpecs;
    }
    /**
     * The current state of the target asset.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current state of the target asset.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * Instance launch details. Use the `sourceDetails` parameter to specify whether a boot volume or an image should be used to launch a new instance.
     * 
     */
    @Export(name="testSpecs", refs={List.class,TargetAssetTestSpec.class}, tree="[0,1]")
    private Output<List<TargetAssetTestSpec>> testSpecs;

    /**
     * @return Instance launch details. Use the `sourceDetails` parameter to specify whether a boot volume or an image should be used to launch a new instance.
     * 
     */
    public Output<List<TargetAssetTestSpec>> testSpecs() {
        return this.testSpecs;
    }
    /**
     * The time when the assessment was done. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeAssessed", refs={String.class}, tree="[0]")
    private Output<String> timeAssessed;

    /**
     * @return The time when the assessment was done. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeAssessed() {
        return this.timeAssessed;
    }
    /**
     * The time when the target asset was created. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The time when the target asset was created. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time when the target asset was updated. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    /**
     * @return The time when the target asset was updated. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * (Updatable) The type of target asset.
     * 
     */
    @Export(name="type", refs={String.class}, tree="[0]")
    private Output<String> type;

    /**
     * @return (Updatable) The type of target asset.
     * 
     */
    public Output<String> type() {
        return this.type;
    }
    /**
     * (Updatable) Instance launch details. Use the `sourceDetails` parameter to specify whether a boot volume or an image should be used to launch a new instance.
     * 
     */
    @Export(name="userSpec", refs={TargetAssetUserSpec.class}, tree="[0]")
    private Output<TargetAssetUserSpec> userSpec;

    /**
     * @return (Updatable) Instance launch details. Use the `sourceDetails` parameter to specify whether a boot volume or an image should be used to launch a new instance.
     * 
     */
    public Output<TargetAssetUserSpec> userSpec() {
        return this.userSpec;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public TargetAsset(java.lang.String name) {
        this(name, TargetAssetArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public TargetAsset(java.lang.String name, TargetAssetArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public TargetAsset(java.lang.String name, TargetAssetArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:CloudMigrations/targetAsset:TargetAsset", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private TargetAsset(java.lang.String name, Output<java.lang.String> id, @Nullable TargetAssetState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:CloudMigrations/targetAsset:TargetAsset", name, state, makeResourceOptions(options, id), false);
    }

    private static TargetAssetArgs makeArgs(TargetAssetArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? TargetAssetArgs.Empty : args;
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
    public static TargetAsset get(java.lang.String name, Output<java.lang.String> id, @Nullable TargetAssetState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new TargetAsset(name, id, state, options);
    }
}
