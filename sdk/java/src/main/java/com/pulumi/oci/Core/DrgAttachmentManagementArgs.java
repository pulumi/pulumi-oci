// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Core.inputs.DrgAttachmentManagementNetworkDetailsArgs;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DrgAttachmentManagementArgs extends com.pulumi.resources.ResourceArgs {

    public static final DrgAttachmentManagementArgs Empty = new DrgAttachmentManagementArgs();

    /**
     * The type for the network resource attached to the DRG.
     * 
     */
    @Import(name="attachmentType", required=true)
    private Output<String> attachmentType;

    /**
     * @return The type for the network resource attached to the DRG.
     * 
     */
    public Output<String> attachmentType() {
        return this.attachmentType;
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG.
     * 
     */
    @Import(name="drgId", required=true)
    private Output<String> drgId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG.
     * 
     */
    public Output<String> drgId() {
        return this.drgId;
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG route table assigned to the DRG attachment.
     * 
     */
    @Import(name="drgRouteTableId")
    private @Nullable Output<String> drgRouteTableId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG route table assigned to the DRG attachment.
     * 
     */
    public Optional<Output<String>> drgRouteTableId() {
        return Optional.ofNullable(this.drgRouteTableId);
    }

    /**
     * - The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the export route distribution used to specify how routes in the assigned DRG route table are advertised to the attachment. If this value is null, no routes are advertised through this attachment.
     * 
     */
    @Import(name="exportDrgRouteDistributionId")
    private @Nullable Output<String> exportDrgRouteDistributionId;

    /**
     * @return - The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the export route distribution used to specify how routes in the assigned DRG route table are advertised to the attachment. If this value is null, no routes are advertised through this attachment.
     * 
     */
    public Optional<Output<String>> exportDrgRouteDistributionId() {
        return Optional.ofNullable(this.exportDrgRouteDistributionId);
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable)
     * 
     */
    @Import(name="networkDetails")
    private @Nullable Output<DrgAttachmentManagementNetworkDetailsArgs> networkDetails;

    /**
     * @return (Updatable)
     * 
     */
    public Optional<Output<DrgAttachmentManagementNetworkDetailsArgs>> networkDetails() {
        return Optional.ofNullable(this.networkDetails);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource (virtual circuit, VCN, IPSec tunnel, or remote peering connection) attached to the DRG.
     * 
     */
    @Import(name="networkId")
    private @Nullable Output<String> networkId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource (virtual circuit, VCN, IPSec tunnel, or remote peering connection) attached to the DRG.
     * 
     */
    public Optional<Output<String>> networkId() {
        return Optional.ofNullable(this.networkId);
    }

    /**
     * (Updatable) An optional property when set to true during update disables the export of route Distribution by setting export_drg_route_distribution_id to null.
     * 
     */
    @Import(name="removeExportDrgRouteDistributionTrigger")
    private @Nullable Output<Boolean> removeExportDrgRouteDistributionTrigger;

    /**
     * @return (Updatable) An optional property when set to true during update disables the export of route Distribution by setting export_drg_route_distribution_id to null.
     * 
     */
    public Optional<Output<Boolean>> removeExportDrgRouteDistributionTrigger() {
        return Optional.ofNullable(this.removeExportDrgRouteDistributionTrigger);
    }

    /**
     * (Updatable)- The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the DRG attachment is using.
     * 
     */
    @Import(name="routeTableId")
    private @Nullable Output<String> routeTableId;

    /**
     * @return (Updatable)- The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the DRG attachment is using.
     * 
     */
    public Optional<Output<String>> routeTableId() {
        return Optional.ofNullable(this.routeTableId);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
     * 
     */
    @Import(name="vcnId")
    private @Nullable Output<String> vcnId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
     * 
     */
    public Optional<Output<String>> vcnId() {
        return Optional.ofNullable(this.vcnId);
    }

    private DrgAttachmentManagementArgs() {}

    private DrgAttachmentManagementArgs(DrgAttachmentManagementArgs $) {
        this.attachmentType = $.attachmentType;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.drgId = $.drgId;
        this.drgRouteTableId = $.drgRouteTableId;
        this.exportDrgRouteDistributionId = $.exportDrgRouteDistributionId;
        this.freeformTags = $.freeformTags;
        this.networkDetails = $.networkDetails;
        this.networkId = $.networkId;
        this.removeExportDrgRouteDistributionTrigger = $.removeExportDrgRouteDistributionTrigger;
        this.routeTableId = $.routeTableId;
        this.vcnId = $.vcnId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DrgAttachmentManagementArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DrgAttachmentManagementArgs $;

        public Builder() {
            $ = new DrgAttachmentManagementArgs();
        }

        public Builder(DrgAttachmentManagementArgs defaults) {
            $ = new DrgAttachmentManagementArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param attachmentType The type for the network resource attached to the DRG.
         * 
         * @return builder
         * 
         */
        public Builder attachmentType(Output<String> attachmentType) {
            $.attachmentType = attachmentType;
            return this;
        }

        /**
         * @param attachmentType The type for the network resource attached to the DRG.
         * 
         * @return builder
         * 
         */
        public Builder attachmentType(String attachmentType) {
            return attachmentType(Output.of(attachmentType));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param drgId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG.
         * 
         * @return builder
         * 
         */
        public Builder drgId(Output<String> drgId) {
            $.drgId = drgId;
            return this;
        }

        /**
         * @param drgId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG.
         * 
         * @return builder
         * 
         */
        public Builder drgId(String drgId) {
            return drgId(Output.of(drgId));
        }

        /**
         * @param drgRouteTableId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG route table assigned to the DRG attachment.
         * 
         * @return builder
         * 
         */
        public Builder drgRouteTableId(@Nullable Output<String> drgRouteTableId) {
            $.drgRouteTableId = drgRouteTableId;
            return this;
        }

        /**
         * @param drgRouteTableId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG route table assigned to the DRG attachment.
         * 
         * @return builder
         * 
         */
        public Builder drgRouteTableId(String drgRouteTableId) {
            return drgRouteTableId(Output.of(drgRouteTableId));
        }

        /**
         * @param exportDrgRouteDistributionId - The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the export route distribution used to specify how routes in the assigned DRG route table are advertised to the attachment. If this value is null, no routes are advertised through this attachment.
         * 
         * @return builder
         * 
         */
        public Builder exportDrgRouteDistributionId(@Nullable Output<String> exportDrgRouteDistributionId) {
            $.exportDrgRouteDistributionId = exportDrgRouteDistributionId;
            return this;
        }

        /**
         * @param exportDrgRouteDistributionId - The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the export route distribution used to specify how routes in the assigned DRG route table are advertised to the attachment. If this value is null, no routes are advertised through this attachment.
         * 
         * @return builder
         * 
         */
        public Builder exportDrgRouteDistributionId(String exportDrgRouteDistributionId) {
            return exportDrgRouteDistributionId(Output.of(exportDrgRouteDistributionId));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param networkDetails (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder networkDetails(@Nullable Output<DrgAttachmentManagementNetworkDetailsArgs> networkDetails) {
            $.networkDetails = networkDetails;
            return this;
        }

        /**
         * @param networkDetails (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder networkDetails(DrgAttachmentManagementNetworkDetailsArgs networkDetails) {
            return networkDetails(Output.of(networkDetails));
        }

        /**
         * @param networkId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource (virtual circuit, VCN, IPSec tunnel, or remote peering connection) attached to the DRG.
         * 
         * @return builder
         * 
         */
        public Builder networkId(@Nullable Output<String> networkId) {
            $.networkId = networkId;
            return this;
        }

        /**
         * @param networkId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource (virtual circuit, VCN, IPSec tunnel, or remote peering connection) attached to the DRG.
         * 
         * @return builder
         * 
         */
        public Builder networkId(String networkId) {
            return networkId(Output.of(networkId));
        }

        /**
         * @param removeExportDrgRouteDistributionTrigger (Updatable) An optional property when set to true during update disables the export of route Distribution by setting export_drg_route_distribution_id to null.
         * 
         * @return builder
         * 
         */
        public Builder removeExportDrgRouteDistributionTrigger(@Nullable Output<Boolean> removeExportDrgRouteDistributionTrigger) {
            $.removeExportDrgRouteDistributionTrigger = removeExportDrgRouteDistributionTrigger;
            return this;
        }

        /**
         * @param removeExportDrgRouteDistributionTrigger (Updatable) An optional property when set to true during update disables the export of route Distribution by setting export_drg_route_distribution_id to null.
         * 
         * @return builder
         * 
         */
        public Builder removeExportDrgRouteDistributionTrigger(Boolean removeExportDrgRouteDistributionTrigger) {
            return removeExportDrgRouteDistributionTrigger(Output.of(removeExportDrgRouteDistributionTrigger));
        }

        /**
         * @param routeTableId (Updatable)- The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the DRG attachment is using.
         * 
         * @return builder
         * 
         */
        public Builder routeTableId(@Nullable Output<String> routeTableId) {
            $.routeTableId = routeTableId;
            return this;
        }

        /**
         * @param routeTableId (Updatable)- The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the DRG attachment is using.
         * 
         * @return builder
         * 
         */
        public Builder routeTableId(String routeTableId) {
            return routeTableId(Output.of(routeTableId));
        }

        /**
         * @param vcnId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
         * 
         * @return builder
         * 
         */
        public Builder vcnId(@Nullable Output<String> vcnId) {
            $.vcnId = vcnId;
            return this;
        }

        /**
         * @param vcnId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
         * 
         * @return builder
         * 
         */
        public Builder vcnId(String vcnId) {
            return vcnId(Output.of(vcnId));
        }

        public DrgAttachmentManagementArgs build() {
            $.attachmentType = Objects.requireNonNull($.attachmentType, "expected parameter 'attachmentType' to be non-null");
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.drgId = Objects.requireNonNull($.drgId, "expected parameter 'drgId' to be non-null");
            return $;
        }
    }

}