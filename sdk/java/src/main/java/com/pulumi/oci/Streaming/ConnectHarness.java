// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Streaming;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Streaming.ConnectHarnessArgs;
import com.pulumi.oci.Streaming.inputs.ConnectHarnessState;
import com.pulumi.oci.Utilities;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Connect Harness resource in Oracle Cloud Infrastructure Streaming service.
 * 
 * Starts the provisioning of a new connect harness.
 * To track the progress of the provisioning, you can periodically call [GetConnectHarness].
 * In the response, the `lifecycleState` parameter of the [ConnectHarness](https://docs.cloud.oracle.com/iaas/api/#/en/streaming/20180418/ConnectHarness/) object tells you its current state.
 * 
 * ## Example Usage
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.Streaming.ConnectHarness;
 * import com.pulumi.oci.Streaming.ConnectHarnessArgs;
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
 *         var testConnectHarness = new ConnectHarness(&#34;testConnectHarness&#34;, ConnectHarnessArgs.builder()        
 *             .compartmentId(var_.compartment_id())
 *             .definedTags(var_.connect_harness_defined_tags())
 *             .freeformTags(Map.of(&#34;Department&#34;, &#34;Finance&#34;))
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * ConnectHarnesses can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:Streaming/connectHarness:ConnectHarness test_connect_harness &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Streaming/connectHarness:ConnectHarness")
public class ConnectHarness extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) The OCID of the compartment that contains the connect harness.
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the compartment that contains the connect harness.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Export(name="definedTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Output<Map<String,Object>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair that is applied with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Export(name="freeformTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair that is applied with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Output<Map<String,Object>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * Any additional details about the current state of the connect harness.
     * 
     */
    @Export(name="lifecycleStateDetails", type=String.class, parameters={})
    private Output<String> lifecycleStateDetails;

    /**
     * @return Any additional details about the current state of the connect harness.
     * 
     */
    public Output<String> lifecycleStateDetails() {
        return this.lifecycleStateDetails;
    }
    /**
     * The name of the connect harness. Avoid entering confidential information.  Example: `JDBCConnector`
     * 
     */
    @Export(name="name", type=String.class, parameters={})
    private Output<String> name;

    /**
     * @return The name of the connect harness. Avoid entering confidential information.  Example: `JDBCConnector`
     * 
     */
    public Output<String> name() {
        return this.name;
    }
    /**
     * The current state of the connect harness.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current state of the connect harness.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The date and time the connect harness was created, expressed in in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2018-04-20T00:00:07.405Z`
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The date and time the connect harness was created, expressed in in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2018-04-20T00:00:07.405Z`
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public ConnectHarness(String name) {
        this(name, ConnectHarnessArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public ConnectHarness(String name, ConnectHarnessArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public ConnectHarness(String name, ConnectHarnessArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Streaming/connectHarness:ConnectHarness", name, args == null ? ConnectHarnessArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private ConnectHarness(String name, Output<String> id, @Nullable ConnectHarnessState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Streaming/connectHarness:ConnectHarness", name, state, makeResourceOptions(options, id));
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
    public static ConnectHarness get(String name, Output<String> id, @Nullable ConnectHarnessState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new ConnectHarness(name, id, state, options);
    }
}