// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Core.outputs.GetVolumeAttachmentsVolumeAttachmentMultipathDevice;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetVolumeAttachmentsVolumeAttachment {
    /**
     * @return The type of volume attachment.
     * 
     */
    private String attachmentType;
    /**
     * @return The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     * 
     */
    private String availabilityDomain;
    /**
     * @return The Challenge-Handshake-Authentication-Protocol (CHAP) secret valid for the associated CHAP user name. (Also called the &#34;CHAP password&#34;.)
     * 
     */
    private String chapSecret;
    /**
     * @return The volume&#39;s system-generated Challenge-Handshake-Authentication-Protocol (CHAP) user name. See [RFC 1994](https://tools.ietf.org/html/rfc1994) for more on CHAP.  Example: `ocid1.volume.oc1.phx.&lt;unique_ID&gt;`
     * 
     */
    private String chapUsername;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     * @deprecated
     * The &#39;compartment_id&#39; field has been deprecated and may be removed in a future version. Do not use this field.
     * 
     */
    @Deprecated /* The 'compartment_id' field has been deprecated and may be removed in a future version. Do not use this field. */
    private String compartmentId;
    /**
     * @return The device name.
     * 
     */
    private String device;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private String displayName;
    /**
     * @return Refer the top-level definition of encryptionInTransitType. The default value is NONE.
     * 
     */
    private String encryptionInTransitType;
    /**
     * @return The OCID of the volume attachment.
     * 
     */
    private String id;
    /**
     * @return The OCID of the instance.
     * 
     */
    private String instanceId;
    /**
     * @return The volume&#39;s iSCSI IP address.  Example: `169.254.2.2`
     * 
     */
    private String ipv4;
    /**
     * @return The target volume&#39;s iSCSI Qualified Name in the format defined by [RFC 3720](https://tools.ietf.org/html/rfc3720#page-32).  Example: `iqn.2015-12.com.oracleiaas:40b7ee03-883f-46c6-a951-63d2841d2195`
     * 
     */
    private String iqn;
    /**
     * @return Whether Oracle Cloud Agent is enabled perform the iSCSI login and logout commands after the volume attach or detach operations for non multipath-enabled iSCSI attachments.
     * 
     */
    private Boolean isAgentAutoIscsiLoginEnabled;
    /**
     * @return Whether the Iscsi or Paravirtualized attachment is multipath or not, it is not applicable to NVMe attachment.
     * 
     */
    private Boolean isMultipath;
    /**
     * @return Whether in-transit encryption for the data volume&#39;s paravirtualized attachment is enabled or not.
     * 
     */
    private Boolean isPvEncryptionInTransitEnabled;
    /**
     * @return Whether the attachment was created in read-only mode.
     * 
     */
    private Boolean isReadOnly;
    /**
     * @return Whether the attachment should be created in shareable mode. If an attachment is created in shareable mode, then other instances can attach the same volume, provided that they also create their attachments in shareable mode. Only certain volume types can be attached in shareable mode. Defaults to false if not specified.
     * 
     */
    private Boolean isShareable;
    /**
     * @return Flag indicating if this volume was created for the customer as part of a simplified launch. Used to determine whether the volume requires deletion on instance termination.
     * 
     */
    private Boolean isVolumeCreatedDuringLaunch;
    /**
     * @return The iscsi login state of the volume attachment. For a Iscsi volume attachment, all iscsi sessions need to be all logged-in or logged-out to be in logged-in or logged-out state.
     * 
     */
    private String iscsiLoginState;
    /**
     * @return A list of secondary multipath devices
     * 
     */
    private List<GetVolumeAttachmentsVolumeAttachmentMultipathDevice> multipathDevices;
    /**
     * @return The volume&#39;s iSCSI port, usually port 860 or 3260.  Example: `3260`
     * 
     */
    private Integer port;
    /**
     * @return The current state of the volume attachment.
     * 
     */
    private String state;
    /**
     * @return The date and time the volume was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeCreated;
    private Boolean useChap;
    /**
     * @return The OCID of the volume.
     * 
     */
    private String volumeId;

    private GetVolumeAttachmentsVolumeAttachment() {}
    /**
     * @return The type of volume attachment.
     * 
     */
    public String attachmentType() {
        return this.attachmentType;
    }
    /**
     * @return The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public String availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * @return The Challenge-Handshake-Authentication-Protocol (CHAP) secret valid for the associated CHAP user name. (Also called the &#34;CHAP password&#34;.)
     * 
     */
    public String chapSecret() {
        return this.chapSecret;
    }
    /**
     * @return The volume&#39;s system-generated Challenge-Handshake-Authentication-Protocol (CHAP) user name. See [RFC 1994](https://tools.ietf.org/html/rfc1994) for more on CHAP.  Example: `ocid1.volume.oc1.phx.&lt;unique_ID&gt;`
     * 
     */
    public String chapUsername() {
        return this.chapUsername;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     * @deprecated
     * The &#39;compartment_id&#39; field has been deprecated and may be removed in a future version. Do not use this field.
     * 
     */
    @Deprecated /* The 'compartment_id' field has been deprecated and may be removed in a future version. Do not use this field. */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The device name.
     * 
     */
    public String device() {
        return this.device;
    }
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Refer the top-level definition of encryptionInTransitType. The default value is NONE.
     * 
     */
    public String encryptionInTransitType() {
        return this.encryptionInTransitType;
    }
    /**
     * @return The OCID of the volume attachment.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The OCID of the instance.
     * 
     */
    public String instanceId() {
        return this.instanceId;
    }
    /**
     * @return The volume&#39;s iSCSI IP address.  Example: `169.254.2.2`
     * 
     */
    public String ipv4() {
        return this.ipv4;
    }
    /**
     * @return The target volume&#39;s iSCSI Qualified Name in the format defined by [RFC 3720](https://tools.ietf.org/html/rfc3720#page-32).  Example: `iqn.2015-12.com.oracleiaas:40b7ee03-883f-46c6-a951-63d2841d2195`
     * 
     */
    public String iqn() {
        return this.iqn;
    }
    /**
     * @return Whether Oracle Cloud Agent is enabled perform the iSCSI login and logout commands after the volume attach or detach operations for non multipath-enabled iSCSI attachments.
     * 
     */
    public Boolean isAgentAutoIscsiLoginEnabled() {
        return this.isAgentAutoIscsiLoginEnabled;
    }
    /**
     * @return Whether the Iscsi or Paravirtualized attachment is multipath or not, it is not applicable to NVMe attachment.
     * 
     */
    public Boolean isMultipath() {
        return this.isMultipath;
    }
    /**
     * @return Whether in-transit encryption for the data volume&#39;s paravirtualized attachment is enabled or not.
     * 
     */
    public Boolean isPvEncryptionInTransitEnabled() {
        return this.isPvEncryptionInTransitEnabled;
    }
    /**
     * @return Whether the attachment was created in read-only mode.
     * 
     */
    public Boolean isReadOnly() {
        return this.isReadOnly;
    }
    /**
     * @return Whether the attachment should be created in shareable mode. If an attachment is created in shareable mode, then other instances can attach the same volume, provided that they also create their attachments in shareable mode. Only certain volume types can be attached in shareable mode. Defaults to false if not specified.
     * 
     */
    public Boolean isShareable() {
        return this.isShareable;
    }
    /**
     * @return Flag indicating if this volume was created for the customer as part of a simplified launch. Used to determine whether the volume requires deletion on instance termination.
     * 
     */
    public Boolean isVolumeCreatedDuringLaunch() {
        return this.isVolumeCreatedDuringLaunch;
    }
    /**
     * @return The iscsi login state of the volume attachment. For a Iscsi volume attachment, all iscsi sessions need to be all logged-in or logged-out to be in logged-in or logged-out state.
     * 
     */
    public String iscsiLoginState() {
        return this.iscsiLoginState;
    }
    /**
     * @return A list of secondary multipath devices
     * 
     */
    public List<GetVolumeAttachmentsVolumeAttachmentMultipathDevice> multipathDevices() {
        return this.multipathDevices;
    }
    /**
     * @return The volume&#39;s iSCSI port, usually port 860 or 3260.  Example: `3260`
     * 
     */
    public Integer port() {
        return this.port;
    }
    /**
     * @return The current state of the volume attachment.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the volume was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    public Boolean useChap() {
        return this.useChap;
    }
    /**
     * @return The OCID of the volume.
     * 
     */
    public String volumeId() {
        return this.volumeId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetVolumeAttachmentsVolumeAttachment defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String attachmentType;
        private String availabilityDomain;
        private String chapSecret;
        private String chapUsername;
        private String compartmentId;
        private String device;
        private String displayName;
        private String encryptionInTransitType;
        private String id;
        private String instanceId;
        private String ipv4;
        private String iqn;
        private Boolean isAgentAutoIscsiLoginEnabled;
        private Boolean isMultipath;
        private Boolean isPvEncryptionInTransitEnabled;
        private Boolean isReadOnly;
        private Boolean isShareable;
        private Boolean isVolumeCreatedDuringLaunch;
        private String iscsiLoginState;
        private List<GetVolumeAttachmentsVolumeAttachmentMultipathDevice> multipathDevices;
        private Integer port;
        private String state;
        private String timeCreated;
        private Boolean useChap;
        private String volumeId;
        public Builder() {}
        public Builder(GetVolumeAttachmentsVolumeAttachment defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.attachmentType = defaults.attachmentType;
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.chapSecret = defaults.chapSecret;
    	      this.chapUsername = defaults.chapUsername;
    	      this.compartmentId = defaults.compartmentId;
    	      this.device = defaults.device;
    	      this.displayName = defaults.displayName;
    	      this.encryptionInTransitType = defaults.encryptionInTransitType;
    	      this.id = defaults.id;
    	      this.instanceId = defaults.instanceId;
    	      this.ipv4 = defaults.ipv4;
    	      this.iqn = defaults.iqn;
    	      this.isAgentAutoIscsiLoginEnabled = defaults.isAgentAutoIscsiLoginEnabled;
    	      this.isMultipath = defaults.isMultipath;
    	      this.isPvEncryptionInTransitEnabled = defaults.isPvEncryptionInTransitEnabled;
    	      this.isReadOnly = defaults.isReadOnly;
    	      this.isShareable = defaults.isShareable;
    	      this.isVolumeCreatedDuringLaunch = defaults.isVolumeCreatedDuringLaunch;
    	      this.iscsiLoginState = defaults.iscsiLoginState;
    	      this.multipathDevices = defaults.multipathDevices;
    	      this.port = defaults.port;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.useChap = defaults.useChap;
    	      this.volumeId = defaults.volumeId;
        }

        @CustomType.Setter
        public Builder attachmentType(String attachmentType) {
            if (attachmentType == null) {
              throw new MissingRequiredPropertyException("GetVolumeAttachmentsVolumeAttachment", "attachmentType");
            }
            this.attachmentType = attachmentType;
            return this;
        }
        @CustomType.Setter
        public Builder availabilityDomain(String availabilityDomain) {
            if (availabilityDomain == null) {
              throw new MissingRequiredPropertyException("GetVolumeAttachmentsVolumeAttachment", "availabilityDomain");
            }
            this.availabilityDomain = availabilityDomain;
            return this;
        }
        @CustomType.Setter
        public Builder chapSecret(String chapSecret) {
            if (chapSecret == null) {
              throw new MissingRequiredPropertyException("GetVolumeAttachmentsVolumeAttachment", "chapSecret");
            }
            this.chapSecret = chapSecret;
            return this;
        }
        @CustomType.Setter
        public Builder chapUsername(String chapUsername) {
            if (chapUsername == null) {
              throw new MissingRequiredPropertyException("GetVolumeAttachmentsVolumeAttachment", "chapUsername");
            }
            this.chapUsername = chapUsername;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetVolumeAttachmentsVolumeAttachment", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder device(String device) {
            if (device == null) {
              throw new MissingRequiredPropertyException("GetVolumeAttachmentsVolumeAttachment", "device");
            }
            this.device = device;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetVolumeAttachmentsVolumeAttachment", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder encryptionInTransitType(String encryptionInTransitType) {
            if (encryptionInTransitType == null) {
              throw new MissingRequiredPropertyException("GetVolumeAttachmentsVolumeAttachment", "encryptionInTransitType");
            }
            this.encryptionInTransitType = encryptionInTransitType;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetVolumeAttachmentsVolumeAttachment", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder instanceId(String instanceId) {
            if (instanceId == null) {
              throw new MissingRequiredPropertyException("GetVolumeAttachmentsVolumeAttachment", "instanceId");
            }
            this.instanceId = instanceId;
            return this;
        }
        @CustomType.Setter
        public Builder ipv4(String ipv4) {
            if (ipv4 == null) {
              throw new MissingRequiredPropertyException("GetVolumeAttachmentsVolumeAttachment", "ipv4");
            }
            this.ipv4 = ipv4;
            return this;
        }
        @CustomType.Setter
        public Builder iqn(String iqn) {
            if (iqn == null) {
              throw new MissingRequiredPropertyException("GetVolumeAttachmentsVolumeAttachment", "iqn");
            }
            this.iqn = iqn;
            return this;
        }
        @CustomType.Setter
        public Builder isAgentAutoIscsiLoginEnabled(Boolean isAgentAutoIscsiLoginEnabled) {
            if (isAgentAutoIscsiLoginEnabled == null) {
              throw new MissingRequiredPropertyException("GetVolumeAttachmentsVolumeAttachment", "isAgentAutoIscsiLoginEnabled");
            }
            this.isAgentAutoIscsiLoginEnabled = isAgentAutoIscsiLoginEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder isMultipath(Boolean isMultipath) {
            if (isMultipath == null) {
              throw new MissingRequiredPropertyException("GetVolumeAttachmentsVolumeAttachment", "isMultipath");
            }
            this.isMultipath = isMultipath;
            return this;
        }
        @CustomType.Setter
        public Builder isPvEncryptionInTransitEnabled(Boolean isPvEncryptionInTransitEnabled) {
            if (isPvEncryptionInTransitEnabled == null) {
              throw new MissingRequiredPropertyException("GetVolumeAttachmentsVolumeAttachment", "isPvEncryptionInTransitEnabled");
            }
            this.isPvEncryptionInTransitEnabled = isPvEncryptionInTransitEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder isReadOnly(Boolean isReadOnly) {
            if (isReadOnly == null) {
              throw new MissingRequiredPropertyException("GetVolumeAttachmentsVolumeAttachment", "isReadOnly");
            }
            this.isReadOnly = isReadOnly;
            return this;
        }
        @CustomType.Setter
        public Builder isShareable(Boolean isShareable) {
            if (isShareable == null) {
              throw new MissingRequiredPropertyException("GetVolumeAttachmentsVolumeAttachment", "isShareable");
            }
            this.isShareable = isShareable;
            return this;
        }
        @CustomType.Setter
        public Builder isVolumeCreatedDuringLaunch(Boolean isVolumeCreatedDuringLaunch) {
            if (isVolumeCreatedDuringLaunch == null) {
              throw new MissingRequiredPropertyException("GetVolumeAttachmentsVolumeAttachment", "isVolumeCreatedDuringLaunch");
            }
            this.isVolumeCreatedDuringLaunch = isVolumeCreatedDuringLaunch;
            return this;
        }
        @CustomType.Setter
        public Builder iscsiLoginState(String iscsiLoginState) {
            if (iscsiLoginState == null) {
              throw new MissingRequiredPropertyException("GetVolumeAttachmentsVolumeAttachment", "iscsiLoginState");
            }
            this.iscsiLoginState = iscsiLoginState;
            return this;
        }
        @CustomType.Setter
        public Builder multipathDevices(List<GetVolumeAttachmentsVolumeAttachmentMultipathDevice> multipathDevices) {
            if (multipathDevices == null) {
              throw new MissingRequiredPropertyException("GetVolumeAttachmentsVolumeAttachment", "multipathDevices");
            }
            this.multipathDevices = multipathDevices;
            return this;
        }
        public Builder multipathDevices(GetVolumeAttachmentsVolumeAttachmentMultipathDevice... multipathDevices) {
            return multipathDevices(List.of(multipathDevices));
        }
        @CustomType.Setter
        public Builder port(Integer port) {
            if (port == null) {
              throw new MissingRequiredPropertyException("GetVolumeAttachmentsVolumeAttachment", "port");
            }
            this.port = port;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetVolumeAttachmentsVolumeAttachment", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetVolumeAttachmentsVolumeAttachment", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder useChap(Boolean useChap) {
            if (useChap == null) {
              throw new MissingRequiredPropertyException("GetVolumeAttachmentsVolumeAttachment", "useChap");
            }
            this.useChap = useChap;
            return this;
        }
        @CustomType.Setter
        public Builder volumeId(String volumeId) {
            if (volumeId == null) {
              throw new MissingRequiredPropertyException("GetVolumeAttachmentsVolumeAttachment", "volumeId");
            }
            this.volumeId = volumeId;
            return this;
        }
        public GetVolumeAttachmentsVolumeAttachment build() {
            final var _resultValue = new GetVolumeAttachmentsVolumeAttachment();
            _resultValue.attachmentType = attachmentType;
            _resultValue.availabilityDomain = availabilityDomain;
            _resultValue.chapSecret = chapSecret;
            _resultValue.chapUsername = chapUsername;
            _resultValue.compartmentId = compartmentId;
            _resultValue.device = device;
            _resultValue.displayName = displayName;
            _resultValue.encryptionInTransitType = encryptionInTransitType;
            _resultValue.id = id;
            _resultValue.instanceId = instanceId;
            _resultValue.ipv4 = ipv4;
            _resultValue.iqn = iqn;
            _resultValue.isAgentAutoIscsiLoginEnabled = isAgentAutoIscsiLoginEnabled;
            _resultValue.isMultipath = isMultipath;
            _resultValue.isPvEncryptionInTransitEnabled = isPvEncryptionInTransitEnabled;
            _resultValue.isReadOnly = isReadOnly;
            _resultValue.isShareable = isShareable;
            _resultValue.isVolumeCreatedDuringLaunch = isVolumeCreatedDuringLaunch;
            _resultValue.iscsiLoginState = iscsiLoginState;
            _resultValue.multipathDevices = multipathDevices;
            _resultValue.port = port;
            _resultValue.state = state;
            _resultValue.timeCreated = timeCreated;
            _resultValue.useChap = useChap;
            _resultValue.volumeId = volumeId;
            return _resultValue;
        }
    }
}
