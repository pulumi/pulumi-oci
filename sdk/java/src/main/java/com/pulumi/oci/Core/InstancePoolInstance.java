// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Core.InstancePoolInstanceArgs;
import com.pulumi.oci.Core.inputs.InstancePoolInstanceState;
import com.pulumi.oci.Core.outputs.InstancePoolInstanceLoadBalancerBackend;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * This resource provides the Instance Pool Instance resource in Oracle Cloud Infrastructure Core service.
 * 
 * Attaches an instance to an instance pool. For information about the prerequisites
 * that an instance must meet before you can attach it to a pool, see
 * [Attaching an Instance to an Instance Pool](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/updatinginstancepool.htm#attach-instance).
 * 
 * Using this resource will impact the size of the instance pool, attach will increment the size of the pool
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
 * import com.pulumi.oci.Core.InstancePoolInstance;
 * import com.pulumi.oci.Core.InstancePoolInstanceArgs;
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
 *         var testInstancePoolInstance = new InstancePoolInstance("testInstancePoolInstance", InstancePoolInstanceArgs.builder()
 *             .instanceId(testInstance.id())
 *             .instancePoolId(testInstancePool.id())
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
 * InstancePoolInstances can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:Core/instancePoolInstance:InstancePoolInstance test_instance_pool_instance &#34;instancePools/{instancePoolId}/instances/compartmentId/{compartmentId}&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Core/instancePoolInstance:InstancePoolInstance")
public class InstancePoolInstance extends com.pulumi.resources.CustomResource {
    @Export(name="autoTerminateInstanceOnDelete", refs={Boolean.class}, tree="[0]")
    private Output</* @Nullable */ Boolean> autoTerminateInstanceOnDelete;

    public Output<Optional<Boolean>> autoTerminateInstanceOnDelete() {
        return Codegen.optional(this.autoTerminateInstanceOnDelete);
    }
    /**
     * The availability domain the instance is running in.
     * 
     */
    @Export(name="availabilityDomain", refs={String.class}, tree="[0]")
    private Output<String> availabilityDomain;

    /**
     * @return The availability domain the instance is running in.
     * 
     */
    public Output<String> availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the instance.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the instance.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    @Export(name="decrementSizeOnDelete", refs={Boolean.class}, tree="[0]")
    private Output</* @Nullable */ Boolean> decrementSizeOnDelete;

    public Output<Optional<Boolean>> decrementSizeOnDelete() {
        return Codegen.optional(this.decrementSizeOnDelete);
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
     * The fault domain the instance is running in.
     * 
     */
    @Export(name="faultDomain", refs={String.class}, tree="[0]")
    private Output<String> faultDomain;

    /**
     * @return The fault domain the instance is running in.
     * 
     */
    public Output<String> faultDomain() {
        return this.faultDomain;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance configuration used to create the instance.
     * 
     */
    @Export(name="instanceConfigurationId", refs={String.class}, tree="[0]")
    private Output<String> instanceConfigurationId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance configuration used to create the instance.
     * 
     */
    public Output<String> instanceConfigurationId() {
        return this.instanceConfigurationId;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance.
     * 
     */
    @Export(name="instanceId", refs={String.class}, tree="[0]")
    private Output<String> instanceId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance.
     * 
     */
    public Output<String> instanceId() {
        return this.instanceId;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance pool.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="instancePoolId", refs={String.class}, tree="[0]")
    private Output<String> instancePoolId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance pool.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> instancePoolId() {
        return this.instancePoolId;
    }
    /**
     * The load balancer backends that are configured for the instance pool instance.
     * 
     */
    @Export(name="loadBalancerBackends", refs={List.class,InstancePoolInstanceLoadBalancerBackend.class}, tree="[0,1]")
    private Output<List<InstancePoolInstanceLoadBalancerBackend>> loadBalancerBackends;

    /**
     * @return The load balancer backends that are configured for the instance pool instance.
     * 
     */
    public Output<List<InstancePoolInstanceLoadBalancerBackend>> loadBalancerBackends() {
        return this.loadBalancerBackends;
    }
    /**
     * The region that contains the availability domain the instance is running in.
     * 
     */
    @Export(name="region", refs={String.class}, tree="[0]")
    private Output<String> region;

    /**
     * @return The region that contains the availability domain the instance is running in.
     * 
     */
    public Output<String> region() {
        return this.region;
    }
    /**
     * The shape of an instance. The shape determines the number of CPUs, amount of memory, and other resources allocated to the instance.
     * 
     */
    @Export(name="shape", refs={String.class}, tree="[0]")
    private Output<String> shape;

    /**
     * @return The shape of an instance. The shape determines the number of CPUs, amount of memory, and other resources allocated to the instance.
     * 
     */
    public Output<String> shape() {
        return this.shape;
    }
    /**
     * The lifecycle state of the instance. Refer to `lifecycleState` in the [Instance](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Instance) resource.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The lifecycle state of the instance. Refer to `lifecycleState` in the [Instance](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Instance) resource.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The date and time the instance pool instance was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The date and time the instance pool instance was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public InstancePoolInstance(java.lang.String name) {
        this(name, InstancePoolInstanceArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public InstancePoolInstance(java.lang.String name, InstancePoolInstanceArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public InstancePoolInstance(java.lang.String name, InstancePoolInstanceArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Core/instancePoolInstance:InstancePoolInstance", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private InstancePoolInstance(java.lang.String name, Output<java.lang.String> id, @Nullable InstancePoolInstanceState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Core/instancePoolInstance:InstancePoolInstance", name, state, makeResourceOptions(options, id), false);
    }

    private static InstancePoolInstanceArgs makeArgs(InstancePoolInstanceArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? InstancePoolInstanceArgs.Empty : args;
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
    public static InstancePoolInstance get(java.lang.String name, Output<java.lang.String> id, @Nullable InstancePoolInstanceState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new InstancePoolInstance(name, id, state, options);
    }
}
