// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opsi;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Opsi.EnterpriseManagerBridgeArgs;
import com.pulumi.oci.Opsi.inputs.EnterpriseManagerBridgeState;
import com.pulumi.oci.Utilities;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Enterprise Manager Bridge resource in Oracle Cloud Infrastructure Opsi service.
 * 
 * Create a Enterprise Manager bridge in Operations Insights.
 * 
 * ## Example Usage
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.Opsi.EnterpriseManagerBridge;
 * import com.pulumi.oci.Opsi.EnterpriseManagerBridgeArgs;
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
 *         var testEnterpriseManagerBridge = new EnterpriseManagerBridge(&#34;testEnterpriseManagerBridge&#34;, EnterpriseManagerBridgeArgs.builder()        
 *             .compartmentId(var_.compartment_id())
 *             .displayName(var_.enterprise_manager_bridge_display_name())
 *             .objectStorageBucketName(oci_objectstorage_bucket.test_bucket().name())
 *             .definedTags(Map.of(&#34;foo-namespace.bar-key&#34;, &#34;value&#34;))
 *             .description(var_.enterprise_manager_bridge_description())
 *             .freeformTags(Map.of(&#34;bar-key&#34;, &#34;value&#34;))
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * EnterpriseManagerBridges can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:Opsi/enterpriseManagerBridge:EnterpriseManagerBridge test_enterprise_manager_bridge &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Opsi/enterpriseManagerBridge:EnterpriseManagerBridge")
public class EnterpriseManagerBridge extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) Compartment identifier of the Enterprise Manager bridge
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return (Updatable) Compartment identifier of the Enterprise Manager bridge
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="definedTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,Object>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) Description of Enterprise Manager Bridge
     * 
     */
    @Export(name="description", type=String.class, parameters={})
    private Output<String> description;

    /**
     * @return (Updatable) Description of Enterprise Manager Bridge
     * 
     */
    public Output<String> description() {
        return this.description;
    }
    /**
     * (Updatable) User-friedly name of Enterprise Manager Bridge that does not have to be unique.
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return (Updatable) User-friedly name of Enterprise Manager Bridge that does not have to be unique.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="freeformTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,Object>> freeformTags() {
        return this.freeformTags;
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
     * Object Storage Bucket Name
     * 
     */
    @Export(name="objectStorageBucketName", type=String.class, parameters={})
    private Output<String> objectStorageBucketName;

    /**
     * @return Object Storage Bucket Name
     * 
     */
    public Output<String> objectStorageBucketName() {
        return this.objectStorageBucketName;
    }
    /**
     * A message describing status of the object storage bucket of this resource. For example, it can be used to provide actionable information about the permission and content validity of the bucket.
     * 
     */
    @Export(name="objectStorageBucketStatusDetails", type=String.class, parameters={})
    private Output<String> objectStorageBucketStatusDetails;

    /**
     * @return A message describing status of the object storage bucket of this resource. For example, it can be used to provide actionable information about the permission and content validity of the bucket.
     * 
     */
    public Output<String> objectStorageBucketStatusDetails() {
        return this.objectStorageBucketStatusDetails;
    }
    /**
     * Object Storage Namespace Name
     * 
     */
    @Export(name="objectStorageNamespaceName", type=String.class, parameters={})
    private Output<String> objectStorageNamespaceName;

    /**
     * @return Object Storage Namespace Name
     * 
     */
    public Output<String> objectStorageNamespaceName() {
        return this.objectStorageNamespaceName;
    }
    /**
     * The current state of the Enterprise Manager bridge.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current state of the Enterprise Manager bridge.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Export(name="systemTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> systemTags;

    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Output<Map<String,Object>> systemTags() {
        return this.systemTags;
    }
    /**
     * The time the the Enterprise Manager bridge was first created. An RFC3339 formatted datetime string
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The time the the Enterprise Manager bridge was first created. An RFC3339 formatted datetime string
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time the Enterprise Manager bridge was updated. An RFC3339 formatted datetime string
     * 
     */
    @Export(name="timeUpdated", type=String.class, parameters={})
    private Output<String> timeUpdated;

    /**
     * @return The time the Enterprise Manager bridge was updated. An RFC3339 formatted datetime string
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public EnterpriseManagerBridge(String name) {
        this(name, EnterpriseManagerBridgeArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public EnterpriseManagerBridge(String name, EnterpriseManagerBridgeArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public EnterpriseManagerBridge(String name, EnterpriseManagerBridgeArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Opsi/enterpriseManagerBridge:EnterpriseManagerBridge", name, args == null ? EnterpriseManagerBridgeArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private EnterpriseManagerBridge(String name, Output<String> id, @Nullable EnterpriseManagerBridgeState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Opsi/enterpriseManagerBridge:EnterpriseManagerBridge", name, state, makeResourceOptions(options, id));
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
    public static EnterpriseManagerBridge get(String name, Output<String> id, @Nullable EnterpriseManagerBridgeState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new EnterpriseManagerBridge(name, id, state, options);
    }
}