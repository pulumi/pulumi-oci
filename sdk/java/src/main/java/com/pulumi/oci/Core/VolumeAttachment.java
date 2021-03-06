// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Core.VolumeAttachmentArgs;
import com.pulumi.oci.Core.inputs.VolumeAttachmentState;
import com.pulumi.oci.Core.outputs.VolumeAttachmentMultipathDevice;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import javax.annotation.Nullable;

/**
 * This resource provides the Volume Attachment resource in Oracle Cloud Infrastructure Core service.
 * 
 * Attaches the specified storage volume to the specified instance.
 * 
 * ## Example Usage
 * 
 * ## Import
 * 
 * VolumeAttachments can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:Core/volumeAttachment:VolumeAttachment test_volume_attachment &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Core/volumeAttachment:VolumeAttachment")
public class VolumeAttachment extends com.pulumi.resources.CustomResource {
    /**
     * The type of volume. The only supported values are &#34;iscsi&#34; and &#34;paravirtualized&#34;.
     * 
     */
    @Export(name="attachmentType", type=String.class, parameters={})
    private Output<String> attachmentType;

    /**
     * @return The type of volume. The only supported values are &#34;iscsi&#34; and &#34;paravirtualized&#34;.
     * 
     */
    public Output<String> attachmentType() {
        return this.attachmentType;
    }
    /**
     * The availability domain of an instance.  Example: `Uocm:PHX-AD-1`
     * 
     */
    @Export(name="availabilityDomain", type=String.class, parameters={})
    private Output<String> availabilityDomain;

    /**
     * @return The availability domain of an instance.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public Output<String> availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * The Challenge-Handshake-Authentication-Protocol (CHAP) secret valid for the associated CHAP user name. (Also called the &#34;CHAP password&#34;.)
     * 
     */
    @Export(name="chapSecret", type=String.class, parameters={})
    private Output<String> chapSecret;

    /**
     * @return The Challenge-Handshake-Authentication-Protocol (CHAP) secret valid for the associated CHAP user name. (Also called the &#34;CHAP password&#34;.)
     * 
     */
    public Output<String> chapSecret() {
        return this.chapSecret;
    }
    /**
     * The volume&#39;s system-generated Challenge-Handshake-Authentication-Protocol (CHAP) user name. See [RFC 1994](https://tools.ietf.org/html/rfc1994) for more on CHAP.  Example: `ocid1.volume.oc1.phx.&lt;unique_ID&gt;`
     * 
     */
    @Export(name="chapUsername", type=String.class, parameters={})
    private Output<String> chapUsername;

    /**
     * @return The volume&#39;s system-generated Challenge-Handshake-Authentication-Protocol (CHAP) user name. See [RFC 1994](https://tools.ietf.org/html/rfc1994) for more on CHAP.  Example: `ocid1.volume.oc1.phx.&lt;unique_ID&gt;`
     * 
     */
    public Output<String> chapUsername() {
        return this.chapUsername;
    }
    /**
     * The OCID of the compartment.
     * 
     * @deprecated
     * The &#39;compartment_id&#39; field has been deprecated and may be removed in a future version. Do not use this field.
     * 
     */
    @Deprecated /* The 'compartment_id' field has been deprecated and may be removed in a future version. Do not use this field. */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return The OCID of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * The device name. To retrieve a list of devices for a given instance, see [ListInstanceDevices](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Device/ListInstanceDevices).
     * 
     */
    @Export(name="device", type=String.class, parameters={})
    private Output<String> device;

    /**
     * @return The device name. To retrieve a list of devices for a given instance, see [ListInstanceDevices](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Device/ListInstanceDevices).
     * 
     */
    public Output<String> device() {
        return this.device;
    }
    /**
     * A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * Refer the top-level definition of encryptionInTransitType. The default value is NONE.
     * 
     */
    @Export(name="encryptionInTransitType", type=String.class, parameters={})
    private Output<String> encryptionInTransitType;

    /**
     * @return Refer the top-level definition of encryptionInTransitType. The default value is NONE.
     * 
     */
    public Output<String> encryptionInTransitType() {
        return this.encryptionInTransitType;
    }
    /**
     * The OCID of the instance.
     * 
     */
    @Export(name="instanceId", type=String.class, parameters={})
    private Output<String> instanceId;

    /**
     * @return The OCID of the instance.
     * 
     */
    public Output<String> instanceId() {
        return this.instanceId;
    }
    /**
     * The volume&#39;s iSCSI IP address.  Example: `169.254.2.2`
     * 
     */
    @Export(name="ipv4", type=String.class, parameters={})
    private Output<String> ipv4;

    /**
     * @return The volume&#39;s iSCSI IP address.  Example: `169.254.2.2`
     * 
     */
    public Output<String> ipv4() {
        return this.ipv4;
    }
    /**
     * The target volume&#39;s iSCSI Qualified Name in the format defined by [RFC 3720](https://tools.ietf.org/html/rfc3720#page-32).  Example: `iqn.2015-12.com.oracleiaas:40b7ee03-883f-46c6-a951-63d2841d2195`
     * 
     */
    @Export(name="iqn", type=String.class, parameters={})
    private Output<String> iqn;

    /**
     * @return The target volume&#39;s iSCSI Qualified Name in the format defined by [RFC 3720](https://tools.ietf.org/html/rfc3720#page-32).  Example: `iqn.2015-12.com.oracleiaas:40b7ee03-883f-46c6-a951-63d2841d2195`
     * 
     */
    public Output<String> iqn() {
        return this.iqn;
    }
    /**
     * Whether the Iscsi or Paravirtualized attachment is multipath or not, it is not applicable to NVMe attachment.
     * 
     */
    @Export(name="isMultipath", type=Boolean.class, parameters={})
    private Output<Boolean> isMultipath;

    /**
     * @return Whether the Iscsi or Paravirtualized attachment is multipath or not, it is not applicable to NVMe attachment.
     * 
     */
    public Output<Boolean> isMultipath() {
        return this.isMultipath;
    }
    /**
     * Whether to enable in-transit encryption for the data volume&#39;s paravirtualized attachment. The default value is false.
     * 
     */
    @Export(name="isPvEncryptionInTransitEnabled", type=Boolean.class, parameters={})
    private Output<Boolean> isPvEncryptionInTransitEnabled;

    /**
     * @return Whether to enable in-transit encryption for the data volume&#39;s paravirtualized attachment. The default value is false.
     * 
     */
    public Output<Boolean> isPvEncryptionInTransitEnabled() {
        return this.isPvEncryptionInTransitEnabled;
    }
    /**
     * Whether the attachment was created in read-only mode.
     * 
     */
    @Export(name="isReadOnly", type=Boolean.class, parameters={})
    private Output<Boolean> isReadOnly;

    /**
     * @return Whether the attachment was created in read-only mode.
     * 
     */
    public Output<Boolean> isReadOnly() {
        return this.isReadOnly;
    }
    /**
     * Whether the attachment should be created in shareable mode. If an attachment is created in shareable mode, then other instances can attach the same volume, provided that they also create their attachments in shareable mode. Only certain volume types can be attached in shareable mode. Defaults to false if not specified.
     * 
     */
    @Export(name="isShareable", type=Boolean.class, parameters={})
    private Output<Boolean> isShareable;

    /**
     * @return Whether the attachment should be created in shareable mode. If an attachment is created in shareable mode, then other instances can attach the same volume, provided that they also create their attachments in shareable mode. Only certain volume types can be attached in shareable mode. Defaults to false if not specified.
     * 
     */
    public Output<Boolean> isShareable() {
        return this.isShareable;
    }
    /**
     * The iscsi login state of the volume attachment. For a Iscsi volume attachment, all iscsi sessions need to be all logged-in or logged-out to be in logged-in or logged-out state.
     * 
     */
    @Export(name="iscsiLoginState", type=String.class, parameters={})
    private Output<String> iscsiLoginState;

    /**
     * @return The iscsi login state of the volume attachment. For a Iscsi volume attachment, all iscsi sessions need to be all logged-in or logged-out to be in logged-in or logged-out state.
     * 
     */
    public Output<String> iscsiLoginState() {
        return this.iscsiLoginState;
    }
    /**
     * A list of secondary multipath devices
     * 
     */
    @Export(name="multipathDevices", type=List.class, parameters={VolumeAttachmentMultipathDevice.class})
    private Output<List<VolumeAttachmentMultipathDevice>> multipathDevices;

    /**
     * @return A list of secondary multipath devices
     * 
     */
    public Output<List<VolumeAttachmentMultipathDevice>> multipathDevices() {
        return this.multipathDevices;
    }
    /**
     * The volume&#39;s iSCSI port, usually port 860 or 3260.  Example: `3260`
     * 
     */
    @Export(name="port", type=Integer.class, parameters={})
    private Output<Integer> port;

    /**
     * @return The volume&#39;s iSCSI port, usually port 860 or 3260.  Example: `3260`
     * 
     */
    public Output<Integer> port() {
        return this.port;
    }
    /**
     * The current state of the volume attachment.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current state of the volume attachment.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The date and time the volume was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The date and time the volume was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * Whether to use CHAP authentication for the volume attachment. Defaults to false.
     * 
     */
    @Export(name="useChap", type=Boolean.class, parameters={})
    private Output<Boolean> useChap;

    /**
     * @return Whether to use CHAP authentication for the volume attachment. Defaults to false.
     * 
     */
    public Output<Boolean> useChap() {
        return this.useChap;
    }
    /**
     * The OCID of the volume.
     * 
     */
    @Export(name="volumeId", type=String.class, parameters={})
    private Output<String> volumeId;

    /**
     * @return The OCID of the volume.
     * 
     */
    public Output<String> volumeId() {
        return this.volumeId;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public VolumeAttachment(String name) {
        this(name, VolumeAttachmentArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public VolumeAttachment(String name, VolumeAttachmentArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public VolumeAttachment(String name, VolumeAttachmentArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Core/volumeAttachment:VolumeAttachment", name, args == null ? VolumeAttachmentArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private VolumeAttachment(String name, Output<String> id, @Nullable VolumeAttachmentState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Core/volumeAttachment:VolumeAttachment", name, state, makeResourceOptions(options, id));
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
    public static VolumeAttachment get(String name, Output<String> id, @Nullable VolumeAttachmentState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new VolumeAttachment(name, id, state, options);
    }
}
