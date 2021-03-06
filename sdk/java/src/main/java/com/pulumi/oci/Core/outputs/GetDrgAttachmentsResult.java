// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetDrgAttachmentsDrgAttachment;
import com.pulumi.oci.Core.outputs.GetDrgAttachmentsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetDrgAttachmentsResult {
    private final @Nullable String attachmentType;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the DRG attachment.
     * 
     */
    private final String compartmentId;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private final @Nullable String displayName;
    /**
     * @return The list of drg_attachments.
     * 
     */
    private final List<GetDrgAttachmentsDrgAttachment> drgAttachments;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG.
     * 
     */
    private final @Nullable String drgId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG route table that is assigned to this attachment.
     * 
     */
    private final @Nullable String drgRouteTableId;
    private final @Nullable List<GetDrgAttachmentsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    private final @Nullable String networkId;
    /**
     * @return The DRG attachment&#39;s current state.
     * 
     */
    private final @Nullable String state;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN. This field is deprecated. Instead, use the `networkDetails` field to view the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the attached resource.
     * 
     */
    private final @Nullable String vcnId;

    @CustomType.Constructor
    private GetDrgAttachmentsResult(
        @CustomType.Parameter("attachmentType") @Nullable String attachmentType,
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("displayName") @Nullable String displayName,
        @CustomType.Parameter("drgAttachments") List<GetDrgAttachmentsDrgAttachment> drgAttachments,
        @CustomType.Parameter("drgId") @Nullable String drgId,
        @CustomType.Parameter("drgRouteTableId") @Nullable String drgRouteTableId,
        @CustomType.Parameter("filters") @Nullable List<GetDrgAttachmentsFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("networkId") @Nullable String networkId,
        @CustomType.Parameter("state") @Nullable String state,
        @CustomType.Parameter("vcnId") @Nullable String vcnId) {
        this.attachmentType = attachmentType;
        this.compartmentId = compartmentId;
        this.displayName = displayName;
        this.drgAttachments = drgAttachments;
        this.drgId = drgId;
        this.drgRouteTableId = drgRouteTableId;
        this.filters = filters;
        this.id = id;
        this.networkId = networkId;
        this.state = state;
        this.vcnId = vcnId;
    }

    public Optional<String> attachmentType() {
        return Optional.ofNullable(this.attachmentType);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the DRG attachment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    /**
     * @return The list of drg_attachments.
     * 
     */
    public List<GetDrgAttachmentsDrgAttachment> drgAttachments() {
        return this.drgAttachments;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG.
     * 
     */
    public Optional<String> drgId() {
        return Optional.ofNullable(this.drgId);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG route table that is assigned to this attachment.
     * 
     */
    public Optional<String> drgRouteTableId() {
        return Optional.ofNullable(this.drgRouteTableId);
    }
    public List<GetDrgAttachmentsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public Optional<String> networkId() {
        return Optional.ofNullable(this.networkId);
    }
    /**
     * @return The DRG attachment&#39;s current state.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN. This field is deprecated. Instead, use the `networkDetails` field to view the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the attached resource.
     * 
     */
    public Optional<String> vcnId() {
        return Optional.ofNullable(this.vcnId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDrgAttachmentsResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable String attachmentType;
        private String compartmentId;
        private @Nullable String displayName;
        private List<GetDrgAttachmentsDrgAttachment> drgAttachments;
        private @Nullable String drgId;
        private @Nullable String drgRouteTableId;
        private @Nullable List<GetDrgAttachmentsFilter> filters;
        private String id;
        private @Nullable String networkId;
        private @Nullable String state;
        private @Nullable String vcnId;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDrgAttachmentsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.attachmentType = defaults.attachmentType;
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.drgAttachments = defaults.drgAttachments;
    	      this.drgId = defaults.drgId;
    	      this.drgRouteTableId = defaults.drgRouteTableId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.networkId = defaults.networkId;
    	      this.state = defaults.state;
    	      this.vcnId = defaults.vcnId;
        }

        public Builder attachmentType(@Nullable String attachmentType) {
            this.attachmentType = attachmentType;
            return this;
        }
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        public Builder drgAttachments(List<GetDrgAttachmentsDrgAttachment> drgAttachments) {
            this.drgAttachments = Objects.requireNonNull(drgAttachments);
            return this;
        }
        public Builder drgAttachments(GetDrgAttachmentsDrgAttachment... drgAttachments) {
            return drgAttachments(List.of(drgAttachments));
        }
        public Builder drgId(@Nullable String drgId) {
            this.drgId = drgId;
            return this;
        }
        public Builder drgRouteTableId(@Nullable String drgRouteTableId) {
            this.drgRouteTableId = drgRouteTableId;
            return this;
        }
        public Builder filters(@Nullable List<GetDrgAttachmentsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetDrgAttachmentsFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder networkId(@Nullable String networkId) {
            this.networkId = networkId;
            return this;
        }
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        public Builder vcnId(@Nullable String vcnId) {
            this.vcnId = vcnId;
            return this;
        }        public GetDrgAttachmentsResult build() {
            return new GetDrgAttachmentsResult(attachmentType, compartmentId, displayName, drgAttachments, drgId, drgRouteTableId, filters, id, networkId, state, vcnId);
        }
    }
}
