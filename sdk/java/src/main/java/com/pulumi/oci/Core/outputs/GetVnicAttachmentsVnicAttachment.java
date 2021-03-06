// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetVnicAttachmentsVnicAttachmentCreateVnicDetail;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetVnicAttachmentsVnicAttachment {
    /**
     * @return The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     * 
     */
    private final String availabilityDomain;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private final String compartmentId;
    private final List<GetVnicAttachmentsVnicAttachmentCreateVnicDetail> createVnicDetails;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private final String displayName;
    /**
     * @return The OCID of the VNIC attachment.
     * 
     */
    private final String id;
    /**
     * @return The OCID of the instance.
     * 
     */
    private final String instanceId;
    /**
     * @return Which physical network interface card (NIC) the VNIC uses. Certain bare metal instance shapes have two active physical NICs (0 and 1). If you add a secondary VNIC to one of these instances, you can specify which NIC the VNIC will use. For more information, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
     * 
     */
    private final Integer nicIndex;
    /**
     * @return The current state of the VNIC attachment.
     * 
     */
    private final String state;
    /**
     * @return The OCID of the subnet to create the VNIC in.
     * 
     */
    private final String subnetId;
    /**
     * @return The date and time the VNIC attachment was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private final String timeCreated;
    /**
     * @return The OCID of the VLAN to create the VNIC in. Creating the VNIC in a VLAN (instead of a subnet) is possible only if you are an Oracle Cloud VMware Solution customer. See [Vlan](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Vlan).
     * 
     */
    private final String vlanId;
    /**
     * @return The Oracle-assigned VLAN tag of the attached VNIC. Available after the attachment process is complete.
     * 
     */
    private final Integer vlanTag;
    /**
     * @return The OCID of the VNIC.
     * 
     */
    private final String vnicId;

    @CustomType.Constructor
    private GetVnicAttachmentsVnicAttachment(
        @CustomType.Parameter("availabilityDomain") String availabilityDomain,
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("createVnicDetails") List<GetVnicAttachmentsVnicAttachmentCreateVnicDetail> createVnicDetails,
        @CustomType.Parameter("displayName") String displayName,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("instanceId") String instanceId,
        @CustomType.Parameter("nicIndex") Integer nicIndex,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("subnetId") String subnetId,
        @CustomType.Parameter("timeCreated") String timeCreated,
        @CustomType.Parameter("vlanId") String vlanId,
        @CustomType.Parameter("vlanTag") Integer vlanTag,
        @CustomType.Parameter("vnicId") String vnicId) {
        this.availabilityDomain = availabilityDomain;
        this.compartmentId = compartmentId;
        this.createVnicDetails = createVnicDetails;
        this.displayName = displayName;
        this.id = id;
        this.instanceId = instanceId;
        this.nicIndex = nicIndex;
        this.state = state;
        this.subnetId = subnetId;
        this.timeCreated = timeCreated;
        this.vlanId = vlanId;
        this.vlanTag = vlanTag;
        this.vnicId = vnicId;
    }

    /**
     * @return The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public String availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<GetVnicAttachmentsVnicAttachmentCreateVnicDetail> createVnicDetails() {
        return this.createVnicDetails;
    }
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return The OCID of the VNIC attachment.
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
     * @return Which physical network interface card (NIC) the VNIC uses. Certain bare metal instance shapes have two active physical NICs (0 and 1). If you add a secondary VNIC to one of these instances, you can specify which NIC the VNIC will use. For more information, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
     * 
     */
    public Integer nicIndex() {
        return this.nicIndex;
    }
    /**
     * @return The current state of the VNIC attachment.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The OCID of the subnet to create the VNIC in.
     * 
     */
    public String subnetId() {
        return this.subnetId;
    }
    /**
     * @return The date and time the VNIC attachment was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The OCID of the VLAN to create the VNIC in. Creating the VNIC in a VLAN (instead of a subnet) is possible only if you are an Oracle Cloud VMware Solution customer. See [Vlan](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Vlan).
     * 
     */
    public String vlanId() {
        return this.vlanId;
    }
    /**
     * @return The Oracle-assigned VLAN tag of the attached VNIC. Available after the attachment process is complete.
     * 
     */
    public Integer vlanTag() {
        return this.vlanTag;
    }
    /**
     * @return The OCID of the VNIC.
     * 
     */
    public String vnicId() {
        return this.vnicId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetVnicAttachmentsVnicAttachment defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String availabilityDomain;
        private String compartmentId;
        private List<GetVnicAttachmentsVnicAttachmentCreateVnicDetail> createVnicDetails;
        private String displayName;
        private String id;
        private String instanceId;
        private Integer nicIndex;
        private String state;
        private String subnetId;
        private String timeCreated;
        private String vlanId;
        private Integer vlanTag;
        private String vnicId;

        public Builder() {
    	      // Empty
        }

        public Builder(GetVnicAttachmentsVnicAttachment defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.compartmentId = defaults.compartmentId;
    	      this.createVnicDetails = defaults.createVnicDetails;
    	      this.displayName = defaults.displayName;
    	      this.id = defaults.id;
    	      this.instanceId = defaults.instanceId;
    	      this.nicIndex = defaults.nicIndex;
    	      this.state = defaults.state;
    	      this.subnetId = defaults.subnetId;
    	      this.timeCreated = defaults.timeCreated;
    	      this.vlanId = defaults.vlanId;
    	      this.vlanTag = defaults.vlanTag;
    	      this.vnicId = defaults.vnicId;
        }

        public Builder availabilityDomain(String availabilityDomain) {
            this.availabilityDomain = Objects.requireNonNull(availabilityDomain);
            return this;
        }
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder createVnicDetails(List<GetVnicAttachmentsVnicAttachmentCreateVnicDetail> createVnicDetails) {
            this.createVnicDetails = Objects.requireNonNull(createVnicDetails);
            return this;
        }
        public Builder createVnicDetails(GetVnicAttachmentsVnicAttachmentCreateVnicDetail... createVnicDetails) {
            return createVnicDetails(List.of(createVnicDetails));
        }
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder instanceId(String instanceId) {
            this.instanceId = Objects.requireNonNull(instanceId);
            return this;
        }
        public Builder nicIndex(Integer nicIndex) {
            this.nicIndex = Objects.requireNonNull(nicIndex);
            return this;
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder subnetId(String subnetId) {
            this.subnetId = Objects.requireNonNull(subnetId);
            return this;
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public Builder vlanId(String vlanId) {
            this.vlanId = Objects.requireNonNull(vlanId);
            return this;
        }
        public Builder vlanTag(Integer vlanTag) {
            this.vlanTag = Objects.requireNonNull(vlanTag);
            return this;
        }
        public Builder vnicId(String vnicId) {
            this.vnicId = Objects.requireNonNull(vnicId);
            return this;
        }        public GetVnicAttachmentsVnicAttachment build() {
            return new GetVnicAttachmentsVnicAttachment(availabilityDomain, compartmentId, createVnicDetails, displayName, id, instanceId, nicIndex, state, subnetId, timeCreated, vlanId, vlanTag, vnicId);
        }
    }
}
