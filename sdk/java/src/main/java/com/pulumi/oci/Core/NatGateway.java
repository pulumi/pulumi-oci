// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Core.NatGatewayArgs;
import com.pulumi.oci.Core.inputs.NatGatewayState;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Nat Gateway resource in Oracle Cloud Infrastructure Core service.
 * 
 * Creates a new NAT gateway for the specified VCN. You must also set up a route rule with the
 * NAT gateway as the rule&#39;s target. See [Route Table](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/RouteTable/).
 * 
 * ## Example Usage
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.Core.NatGateway;
 * import com.pulumi.oci.Core.NatGatewayArgs;
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
 *         var testNatGateway = new NatGateway(&#34;testNatGateway&#34;, NatGatewayArgs.builder()        
 *             .compartmentId(var_.compartment_id())
 *             .vcnId(oci_core_vcn.test_vcn().id())
 *             .blockTraffic(var_.nat_gateway_block_traffic())
 *             .definedTags(Map.of(&#34;Operations.CostCenter&#34;, &#34;42&#34;))
 *             .displayName(var_.nat_gateway_display_name())
 *             .freeformTags(Map.of(&#34;Department&#34;, &#34;Finance&#34;))
 *             .publicIpId(oci_core_public_ip.test_public_ip().id())
 *             .routeTableId(oci_core_route_table.test_route_table().id())
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * NatGateways can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:Core/natGateway:NatGateway test_nat_gateway &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Core/natGateway:NatGateway")
public class NatGateway extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) Whether the NAT gateway blocks traffic through it. The default is `false`.  Example: `true`
     * 
     */
    @Export(name="blockTraffic", type=Boolean.class, parameters={})
    private Output<Boolean> blockTraffic;

    /**
     * @return (Updatable) Whether the NAT gateway blocks traffic through it. The default is `false`.  Example: `true`
     * 
     */
    public Output<Boolean> blockTraffic() {
        return this.blockTraffic;
    }
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the NAT gateway.
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the NAT gateway.
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
     * (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Export(name="freeformTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Output<Map<String,Object>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * The IP address associated with the NAT gateway.
     * 
     */
    @Export(name="natIp", type=String.class, parameters={})
    private Output<String> natIp;

    /**
     * @return The IP address associated with the NAT gateway.
     * 
     */
    public Output<String> natIp() {
        return this.natIp;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the public IP address associated with the NAT gateway.
     * 
     */
    @Export(name="publicIpId", type=String.class, parameters={})
    private Output<String> publicIpId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the public IP address associated with the NAT gateway.
     * 
     */
    public Output<String> publicIpId() {
        return this.publicIpId;
    }
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table used by the NAT gateway.
     * 
     */
    @Export(name="routeTableId", type=String.class, parameters={})
    private Output<String> routeTableId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table used by the NAT gateway.
     * 
     */
    public Output<String> routeTableId() {
        return this.routeTableId;
    }
    /**
     * The NAT gateway&#39;s current state.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The NAT gateway&#39;s current state.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The date and time the NAT gateway was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The date and time the NAT gateway was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN the gateway belongs to.
     * 
     */
    @Export(name="vcnId", type=String.class, parameters={})
    private Output<String> vcnId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN the gateway belongs to.
     * 
     */
    public Output<String> vcnId() {
        return this.vcnId;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public NatGateway(String name) {
        this(name, NatGatewayArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public NatGateway(String name, NatGatewayArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public NatGateway(String name, NatGatewayArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Core/natGateway:NatGateway", name, args == null ? NatGatewayArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private NatGateway(String name, Output<String> id, @Nullable NatGatewayState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Core/natGateway:NatGateway", name, state, makeResourceOptions(options, id));
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
    public static NatGateway get(String name, Output<String> id, @Nullable NatGatewayState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new NatGateway(name, id, state, options);
    }
}