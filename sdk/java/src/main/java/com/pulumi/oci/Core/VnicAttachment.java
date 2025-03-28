// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Core.VnicAttachmentArgs;
import com.pulumi.oci.Core.inputs.VnicAttachmentState;
import com.pulumi.oci.Core.outputs.VnicAttachmentCreateVnicDetails;
import com.pulumi.oci.Utilities;
import java.lang.Integer;
import java.lang.String;
import javax.annotation.Nullable;

/**
 * This resource provides the Vnic Attachment resource in Oracle Cloud Infrastructure Core service.
 * 
 * Creates a secondary VNIC and attaches it to the specified instance.
 * For more information about secondary VNICs, see
 * [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
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
 * import com.pulumi.oci.Core.VnicAttachment;
 * import com.pulumi.oci.Core.VnicAttachmentArgs;
 * import com.pulumi.oci.Core.inputs.VnicAttachmentCreateVnicDetailsArgs;
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
 *         var testVnicAttachment = new VnicAttachment("testVnicAttachment", VnicAttachmentArgs.builder()
 *             .createVnicDetails(VnicAttachmentCreateVnicDetailsArgs.builder()
 *                 .assignIpv6ip(vnicAttachmentCreateVnicDetailsAssignIpv6ip)
 *                 .assignPrivateDnsRecord(vnicAttachmentCreateVnicDetailsAssignPrivateDnsRecord)
 *                 .assignPublicIp(vnicAttachmentCreateVnicDetailsAssignPublicIp)
 *                 .definedTags(vnicAttachmentCreateVnicDetailsDefinedTags)
 *                 .displayName(vnicAttachmentCreateVnicDetailsDisplayName)
 *                 .freeformTags(vnicAttachmentCreateVnicDetailsFreeformTags)
 *                 .hostnameLabel(vnicAttachmentCreateVnicDetailsHostnameLabel)
 *                 .ipv6addressIpv6subnetCidrPairDetails(vnicAttachmentCreateVnicDetailsIpv6addressIpv6subnetCidrPairDetails)
 *                 .nsgIds(vnicAttachmentCreateVnicDetailsNsgIds)
 *                 .privateIp(vnicAttachmentCreateVnicDetailsPrivateIp)
 *                 .securityAttributes(vnicAttachmentCreateVnicDetailsSecurityAttributes)
 *                 .skipSourceDestCheck(vnicAttachmentCreateVnicDetailsSkipSourceDestCheck)
 *                 .subnetId(testSubnet.id())
 *                 .vlanId(testVlan.id())
 *                 .build())
 *             .instanceId(testInstance.id())
 *             .displayName(vnicAttachmentDisplayName)
 *             .nicIndex(vnicAttachmentNicIndex)
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
 * VnicAttachments can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:Core/vnicAttachment:VnicAttachment test_vnic_attachment &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Core/vnicAttachment:VnicAttachment")
public class VnicAttachment extends com.pulumi.resources.CustomResource {
    /**
     * The availability domain of the instance.  Example: `Uocm:PHX-AD-1`
     * 
     */
    @Export(name="availabilityDomain", refs={String.class}, tree="[0]")
    private Output<String> availabilityDomain;

    /**
     * @return The availability domain of the instance.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public Output<String> availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * The OCID of the compartment the VNIC attachment is in, which is the same compartment the instance is in.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return The OCID of the compartment the VNIC attachment is in, which is the same compartment the instance is in.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Contains properties for a VNIC. You use this object when creating the primary VNIC during instance launch or when creating a secondary VNIC. For more information about VNICs, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
     * 
     */
    @Export(name="createVnicDetails", refs={VnicAttachmentCreateVnicDetails.class}, tree="[0]")
    private Output<VnicAttachmentCreateVnicDetails> createVnicDetails;

    /**
     * @return (Updatable) Contains properties for a VNIC. You use this object when creating the primary VNIC during instance launch or when creating a secondary VNIC. For more information about VNICs, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
     * 
     */
    public Output<VnicAttachmentCreateVnicDetails> createVnicDetails() {
        return this.createVnicDetails;
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
     * The OCID of the instance.
     * 
     */
    @Export(name="instanceId", refs={String.class}, tree="[0]")
    private Output<String> instanceId;

    /**
     * @return The OCID of the instance.
     * 
     */
    public Output<String> instanceId() {
        return this.instanceId;
    }
    /**
     * Which physical network interface card (NIC) the VNIC will use. Defaults to 0. Certain bare metal instance shapes have two active physical NICs (0 and 1). If you add a secondary VNIC to one of these instances, you can specify which NIC the VNIC will use. For more information, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="nicIndex", refs={Integer.class}, tree="[0]")
    private Output<Integer> nicIndex;

    /**
     * @return Which physical network interface card (NIC) the VNIC will use. Defaults to 0. Certain bare metal instance shapes have two active physical NICs (0 and 1). If you add a secondary VNIC to one of these instances, you can specify which NIC the VNIC will use. For more information, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<Integer> nicIndex() {
        return this.nicIndex;
    }
    /**
     * The current state of the VNIC attachment.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current state of the VNIC attachment.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The OCID of the subnet to create the VNIC in.
     * 
     */
    @Export(name="subnetId", refs={String.class}, tree="[0]")
    private Output<String> subnetId;

    /**
     * @return The OCID of the subnet to create the VNIC in.
     * 
     */
    public Output<String> subnetId() {
        return this.subnetId;
    }
    /**
     * The date and time the VNIC attachment was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The date and time the VNIC attachment was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The OCID of the VLAN to create the VNIC in. Creating the VNIC in a VLAN (instead of a subnet) is possible only if you are an Oracle Cloud VMware Solution customer. See [Vlan](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Vlan).
     * 
     */
    @Export(name="vlanId", refs={String.class}, tree="[0]")
    private Output<String> vlanId;

    /**
     * @return The OCID of the VLAN to create the VNIC in. Creating the VNIC in a VLAN (instead of a subnet) is possible only if you are an Oracle Cloud VMware Solution customer. See [Vlan](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Vlan).
     * 
     */
    public Output<String> vlanId() {
        return this.vlanId;
    }
    /**
     * The Oracle-assigned VLAN tag of the attached VNIC. Available after the attachment process is complete.
     * 
     */
    @Export(name="vlanTag", refs={Integer.class}, tree="[0]")
    private Output<Integer> vlanTag;

    /**
     * @return The Oracle-assigned VLAN tag of the attached VNIC. Available after the attachment process is complete.
     * 
     */
    public Output<Integer> vlanTag() {
        return this.vlanTag;
    }
    /**
     * The OCID of the VNIC. Available after the attachment process is complete.
     * 
     */
    @Export(name="vnicId", refs={String.class}, tree="[0]")
    private Output<String> vnicId;

    /**
     * @return The OCID of the VNIC. Available after the attachment process is complete.
     * 
     */
    public Output<String> vnicId() {
        return this.vnicId;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public VnicAttachment(java.lang.String name) {
        this(name, VnicAttachmentArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public VnicAttachment(java.lang.String name, VnicAttachmentArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public VnicAttachment(java.lang.String name, VnicAttachmentArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Core/vnicAttachment:VnicAttachment", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private VnicAttachment(java.lang.String name, Output<java.lang.String> id, @Nullable VnicAttachmentState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Core/vnicAttachment:VnicAttachment", name, state, makeResourceOptions(options, id), false);
    }

    private static VnicAttachmentArgs makeArgs(VnicAttachmentArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? VnicAttachmentArgs.Empty : args;
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
    public static VnicAttachment get(java.lang.String name, Output<java.lang.String> id, @Nullable VnicAttachmentState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new VnicAttachment(name, id, state, options);
    }
}
