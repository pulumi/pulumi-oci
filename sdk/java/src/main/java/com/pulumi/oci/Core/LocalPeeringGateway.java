// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Core.LocalPeeringGatewayArgs;
import com.pulumi.oci.Core.inputs.LocalPeeringGatewayState;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Local Peering Gateway resource in Oracle Cloud Infrastructure Core service.
 * 
 * Creates a new local peering gateway (LPG) for the specified VCN.
 * 
 * ## Example Usage
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.Core.LocalPeeringGateway;
 * import com.pulumi.oci.Core.LocalPeeringGatewayArgs;
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
 *         var testLocalPeeringGateway = new LocalPeeringGateway(&#34;testLocalPeeringGateway&#34;, LocalPeeringGatewayArgs.builder()        
 *             .compartmentId(var_.compartment_id())
 *             .vcnId(oci_core_vcn.test_vcn().id())
 *             .definedTags(Map.of(&#34;Operations.CostCenter&#34;, &#34;42&#34;))
 *             .displayName(var_.local_peering_gateway_display_name())
 *             .freeformTags(Map.of(&#34;Department&#34;, &#34;Finance&#34;))
 *             .peerId(oci_core_local_peering_gateway.test_local_peering_gateway2().id())
 *             .routeTableId(oci_core_route_table.test_route_table().id())
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * LocalPeeringGateways can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:Core/localPeeringGateway:LocalPeeringGateway test_local_peering_gateway &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Core/localPeeringGateway:LocalPeeringGateway")
public class LocalPeeringGateway extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the local peering gateway (LPG).
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the local peering gateway (LPG).
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
     * Whether the VCN at the other end of the peering is in a different tenancy.  Example: `false`
     * 
     */
    @Export(name="isCrossTenancyPeering", type=Boolean.class, parameters={})
    private Output<Boolean> isCrossTenancyPeering;

    /**
     * @return Whether the VCN at the other end of the peering is in a different tenancy.  Example: `false`
     * 
     */
    public Output<Boolean> isCrossTenancyPeering() {
        return this.isCrossTenancyPeering;
    }
    /**
     * The smallest aggregate CIDR that contains all the CIDR routes advertised by the VCN at the other end of the peering from this LPG. See `peerAdvertisedCidrDetails` for the individual CIDRs. The value is `null` if the LPG is not peered.  Example: `192.168.0.0/16`, or if aggregated with `172.16.0.0/24` then `128.0.0.0/1`
     * 
     */
    @Export(name="peerAdvertisedCidr", type=String.class, parameters={})
    private Output<String> peerAdvertisedCidr;

    /**
     * @return The smallest aggregate CIDR that contains all the CIDR routes advertised by the VCN at the other end of the peering from this LPG. See `peerAdvertisedCidrDetails` for the individual CIDRs. The value is `null` if the LPG is not peered.  Example: `192.168.0.0/16`, or if aggregated with `172.16.0.0/24` then `128.0.0.0/1`
     * 
     */
    public Output<String> peerAdvertisedCidr() {
        return this.peerAdvertisedCidr;
    }
    /**
     * The specific ranges of IP addresses available on or via the VCN at the other end of the peering from this LPG. The value is `null` if the LPG is not peered. You can use these as destination CIDRs for route rules to route a subnet&#39;s traffic to this LPG.  Example: [`192.168.0.0/16`, `172.16.0.0/24`]
     * 
     */
    @Export(name="peerAdvertisedCidrDetails", type=List.class, parameters={String.class})
    private Output<List<String>> peerAdvertisedCidrDetails;

    /**
     * @return The specific ranges of IP addresses available on or via the VCN at the other end of the peering from this LPG. The value is `null` if the LPG is not peered. You can use these as destination CIDRs for route rules to route a subnet&#39;s traffic to this LPG.  Example: [`192.168.0.0/16`, `172.16.0.0/24`]
     * 
     */
    public Output<List<String>> peerAdvertisedCidrDetails() {
        return this.peerAdvertisedCidrDetails;
    }
    /**
     * The OCID of the LPG you want to peer with. Specifying a peer_id connects this local peering gateway (LPG) to another one in the same region. This operation must be called by the VCN administrator who is designated as the *requestor* in the peering relationship. The *acceptor* must implement an Identity and Access Management (IAM) policy that gives the requestor permission to connect to LPGs in the acceptor&#39;s compartment. Without that permission, this operation will fail. For more information, see [VCN Peering](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/VCNpeering.htm).
     * 
     */
    @Export(name="peerId", type=String.class, parameters={})
    private Output<String> peerId;

    /**
     * @return The OCID of the LPG you want to peer with. Specifying a peer_id connects this local peering gateway (LPG) to another one in the same region. This operation must be called by the VCN administrator who is designated as the *requestor* in the peering relationship. The *acceptor* must implement an Identity and Access Management (IAM) policy that gives the requestor permission to connect to LPGs in the acceptor&#39;s compartment. Without that permission, this operation will fail. For more information, see [VCN Peering](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/VCNpeering.htm).
     * 
     */
    public Output<String> peerId() {
        return this.peerId;
    }
    /**
     * Whether the LPG is peered with another LPG. `NEW` means the LPG has not yet been peered. `PENDING` means the peering is being established. `REVOKED` means the LPG at the other end of the peering has been deleted.
     * 
     */
    @Export(name="peeringStatus", type=String.class, parameters={})
    private Output<String> peeringStatus;

    /**
     * @return Whether the LPG is peered with another LPG. `NEW` means the LPG has not yet been peered. `PENDING` means the peering is being established. `REVOKED` means the LPG at the other end of the peering has been deleted.
     * 
     */
    public Output<String> peeringStatus() {
        return this.peeringStatus;
    }
    /**
     * Additional information regarding the peering status, if applicable.
     * 
     */
    @Export(name="peeringStatusDetails", type=String.class, parameters={})
    private Output<String> peeringStatusDetails;

    /**
     * @return Additional information regarding the peering status, if applicable.
     * 
     */
    public Output<String> peeringStatusDetails() {
        return this.peeringStatusDetails;
    }
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the LPG will use.
     * 
     */
    @Export(name="routeTableId", type=String.class, parameters={})
    private Output<String> routeTableId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the LPG will use.
     * 
     */
    public Output<String> routeTableId() {
        return this.routeTableId;
    }
    /**
     * The LPG&#39;s current lifecycle state.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The LPG&#39;s current lifecycle state.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The date and time the LPG was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The date and time the LPG was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN the LPG belongs to.
     * 
     */
    @Export(name="vcnId", type=String.class, parameters={})
    private Output<String> vcnId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN the LPG belongs to.
     * 
     */
    public Output<String> vcnId() {
        return this.vcnId;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public LocalPeeringGateway(String name) {
        this(name, LocalPeeringGatewayArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public LocalPeeringGateway(String name, LocalPeeringGatewayArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public LocalPeeringGateway(String name, LocalPeeringGatewayArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Core/localPeeringGateway:LocalPeeringGateway", name, args == null ? LocalPeeringGatewayArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private LocalPeeringGateway(String name, Output<String> id, @Nullable LocalPeeringGatewayState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Core/localPeeringGateway:LocalPeeringGateway", name, state, makeResourceOptions(options, id));
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
    public static LocalPeeringGateway get(String name, Output<String> id, @Nullable LocalPeeringGatewayState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new LocalPeeringGateway(name, id, state, options);
    }
}