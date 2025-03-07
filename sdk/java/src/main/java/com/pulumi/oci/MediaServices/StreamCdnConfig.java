// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MediaServices;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.MediaServices.StreamCdnConfigArgs;
import com.pulumi.oci.MediaServices.inputs.StreamCdnConfigState;
import com.pulumi.oci.MediaServices.outputs.StreamCdnConfigConfig;
import com.pulumi.oci.MediaServices.outputs.StreamCdnConfigLock;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Stream Cdn Config resource in Oracle Cloud Infrastructure Media Services service.
 * 
 * Creates a new CDN Configuration.
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
 * import com.pulumi.oci.MediaServices.StreamCdnConfig;
 * import com.pulumi.oci.MediaServices.StreamCdnConfigArgs;
 * import com.pulumi.oci.MediaServices.inputs.StreamCdnConfigConfigArgs;
 * import com.pulumi.oci.MediaServices.inputs.StreamCdnConfigLockArgs;
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
 *         var testStreamCdnConfig = new StreamCdnConfig("testStreamCdnConfig", StreamCdnConfigArgs.builder()
 *             .config(StreamCdnConfigConfigArgs.builder()
 *                 .type(streamCdnConfigConfigType)
 *                 .edgeHostname(streamCdnConfigConfigEdgeHostname)
 *                 .edgePathPrefix(streamCdnConfigConfigEdgePathPrefix)
 *                 .edgeTokenKey(streamCdnConfigConfigEdgeTokenKey)
 *                 .edgeTokenSalt(streamCdnConfigConfigEdgeTokenSalt)
 *                 .isEdgeTokenAuth(streamCdnConfigConfigIsEdgeTokenAuth)
 *                 .originAuthSecretKeyA(streamCdnConfigConfigOriginAuthSecretKeyA)
 *                 .originAuthSecretKeyB(streamCdnConfigConfigOriginAuthSecretKeyB)
 *                 .originAuthSecretKeyNonceA(streamCdnConfigConfigOriginAuthSecretKeyNonceA)
 *                 .originAuthSecretKeyNonceB(streamCdnConfigConfigOriginAuthSecretKeyNonceB)
 *                 .originAuthSignEncryption(streamCdnConfigConfigOriginAuthSignEncryption)
 *                 .originAuthSignType(streamCdnConfigConfigOriginAuthSignType)
 *                 .build())
 *             .displayName(streamCdnConfigDisplayName)
 *             .distributionChannelId(testChannel.id())
 *             .definedTags(Map.of("foo-namespace.bar-key", "value"))
 *             .freeformTags(Map.of("bar-key", "value"))
 *             .isEnabled(streamCdnConfigIsEnabled)
 *             .locks(StreamCdnConfigLockArgs.builder()
 *                 .compartmentId(compartmentId)
 *                 .type(streamCdnConfigLocksType)
 *                 .message(streamCdnConfigLocksMessage)
 *                 .relatedResourceId(testResource.id())
 *                 .timeCreated(streamCdnConfigLocksTimeCreated)
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
 * StreamCdnConfigs can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:MediaServices/streamCdnConfig:StreamCdnConfig test_stream_cdn_config &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:MediaServices/streamCdnConfig:StreamCdnConfig")
public class StreamCdnConfig extends com.pulumi.resources.CustomResource {
    /**
     * The compartment ID of the lock.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return The compartment ID of the lock.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Base fields of the StreamCdnConfig configuration object.
     * 
     */
    @Export(name="config", refs={StreamCdnConfigConfig.class}, tree="[0]")
    private Output<StreamCdnConfigConfig> config;

    /**
     * @return (Updatable) Base fields of the StreamCdnConfig configuration object.
     * 
     */
    public Output<StreamCdnConfigConfig> config() {
        return this.config;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="definedTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,String>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) CDN Config display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
     * 
     */
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    /**
     * @return (Updatable) CDN Config display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * Distribution Channel Identifier.
     * 
     */
    @Export(name="distributionChannelId", refs={String.class}, tree="[0]")
    private Output<String> distributionChannelId;

    /**
     * @return Distribution Channel Identifier.
     * 
     */
    public Output<String> distributionChannelId() {
        return this.distributionChannelId;
    }
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="freeformTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,String>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * (Updatable) Whether publishing to CDN is enabled.
     * 
     */
    @Export(name="isEnabled", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> isEnabled;

    /**
     * @return (Updatable) Whether publishing to CDN is enabled.
     * 
     */
    public Output<Boolean> isEnabled() {
        return this.isEnabled;
    }
    @Export(name="isLockOverride", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> isLockOverride;

    public Output<Boolean> isLockOverride() {
        return this.isLockOverride;
    }
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    @Export(name="lifecyleDetails", refs={String.class}, tree="[0]")
    private Output<String> lifecyleDetails;

    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public Output<String> lifecyleDetails() {
        return this.lifecyleDetails;
    }
    /**
     * Locks associated with this resource.
     * 
     */
    @Export(name="locks", refs={List.class,StreamCdnConfigLock.class}, tree="[0,1]")
    private Output<List<StreamCdnConfigLock>> locks;

    /**
     * @return Locks associated with this resource.
     * 
     */
    public Output<List<StreamCdnConfigLock>> locks() {
        return this.locks;
    }
    /**
     * The current state of the CDN Configuration.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current state of the CDN Configuration.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Export(name="systemTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> systemTags;

    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Output<Map<String,String>> systemTags() {
        return this.systemTags;
    }
    /**
     * The time when the CDN Config was created. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The time when the CDN Config was created. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time when the CDN Config was updated. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    /**
     * @return The time when the CDN Config was updated. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public StreamCdnConfig(java.lang.String name) {
        this(name, StreamCdnConfigArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public StreamCdnConfig(java.lang.String name, StreamCdnConfigArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public StreamCdnConfig(java.lang.String name, StreamCdnConfigArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:MediaServices/streamCdnConfig:StreamCdnConfig", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private StreamCdnConfig(java.lang.String name, Output<java.lang.String> id, @Nullable StreamCdnConfigState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:MediaServices/streamCdnConfig:StreamCdnConfig", name, state, makeResourceOptions(options, id), false);
    }

    private static StreamCdnConfigArgs makeArgs(StreamCdnConfigArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? StreamCdnConfigArgs.Empty : args;
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
    public static StreamCdnConfig get(java.lang.String name, Output<java.lang.String> id, @Nullable StreamCdnConfigState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new StreamCdnConfig(name, id, state, options);
    }
}
