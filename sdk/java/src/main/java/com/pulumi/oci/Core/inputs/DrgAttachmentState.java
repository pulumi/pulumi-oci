// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Core.inputs.DrgAttachmentNetworkDetailsArgs;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DrgAttachmentState extends com.pulumi.resources.ResourceArgs {

    public static final DrgAttachmentState Empty = new DrgAttachmentState();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the DRG attachment.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the DRG attachment.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
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
    @Import(name="drgId")
    private @Nullable Output<String> drgId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG.
     * 
     */
    public Optional<Output<String>> drgId() {
        return Optional.ofNullable(this.drgId);
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG route table that is assigned to this attachment.
     * 
     */
    @Import(name="drgRouteTableId")
    private @Nullable Output<String> drgRouteTableId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG route table that is assigned to this attachment.
     * 
     */
    public Optional<Output<String>> drgRouteTableId() {
        return Optional.ofNullable(this.drgRouteTableId);
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the export route distribution used to specify how routes in the assigned DRG route table are advertised to the attachment. If this value is null, no routes are advertised through this attachment.
     * This field cannot be set by the user while creating the resource and gets a default value on creation. This can be only be updated to its default value. If this fields needs to be set to null, remove_export_drg_route_distribution_trigger needs to be used.
     * 
     */
    @Import(name="exportDrgRouteDistributionId")
    private @Nullable Output<String> exportDrgRouteDistributionId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the export route distribution used to specify how routes in the assigned DRG route table are advertised to the attachment. If this value is null, no routes are advertised through this attachment.
     * This field cannot be set by the user while creating the resource and gets a default value on creation. This can be only be updated to its default value. If this fields needs to be set to null, remove_export_drg_route_distribution_trigger needs to be used.
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
     * Indicates whether the DRG attachment and attached network live in a different tenancy than the DRG.  Example: `false`
     * 
     */
    @Import(name="isCrossTenancy")
    private @Nullable Output<Boolean> isCrossTenancy;

    /**
     * @return Indicates whether the DRG attachment and attached network live in a different tenancy than the DRG.  Example: `false`
     * 
     */
    public Optional<Output<Boolean>> isCrossTenancy() {
        return Optional.ofNullable(this.isCrossTenancy);
    }

    /**
     * (Updatable)
     * 
     */
    @Import(name="networkDetails")
    private @Nullable Output<DrgAttachmentNetworkDetailsArgs> networkDetails;

    /**
     * @return (Updatable)
     * 
     */
    public Optional<Output<DrgAttachmentNetworkDetailsArgs>> networkDetails() {
        return Optional.ofNullable(this.networkDetails);
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
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table used by the DRG attachment.
     * 
     */
    @Import(name="routeTableId")
    private @Nullable Output<String> routeTableId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table used by the DRG attachment.
     * 
     */
    public Optional<Output<String>> routeTableId() {
        return Optional.ofNullable(this.routeTableId);
    }

    /**
     * The DRG attachment&#39;s current state.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The DRG attachment&#39;s current state.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The date and time the DRG attachment was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time the DRG attachment was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * (Optional) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN. This field is deprecated. Instead, use the `networkDetails` field to specify the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the attached resource.
     * 
     */
    @Import(name="vcnId")
    private @Nullable Output<String> vcnId;

    /**
     * @return (Optional) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN. This field is deprecated. Instead, use the `networkDetails` field to specify the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the attached resource.
     * 
     */
    public Optional<Output<String>> vcnId() {
        return Optional.ofNullable(this.vcnId);
    }

    private DrgAttachmentState() {}

    private DrgAttachmentState(DrgAttachmentState $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.drgId = $.drgId;
        this.drgRouteTableId = $.drgRouteTableId;
        this.exportDrgRouteDistributionId = $.exportDrgRouteDistributionId;
        this.freeformTags = $.freeformTags;
        this.isCrossTenancy = $.isCrossTenancy;
        this.networkDetails = $.networkDetails;
        this.removeExportDrgRouteDistributionTrigger = $.removeExportDrgRouteDistributionTrigger;
        this.routeTableId = $.routeTableId;
        this.state = $.state;
        this.timeCreated = $.timeCreated;
        this.vcnId = $.vcnId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DrgAttachmentState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DrgAttachmentState $;

        public Builder() {
            $ = new DrgAttachmentState();
        }

        public Builder(DrgAttachmentState defaults) {
            $ = new DrgAttachmentState(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the DRG attachment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the DRG attachment.
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
        public Builder drgId(@Nullable Output<String> drgId) {
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
         * @param drgRouteTableId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG route table that is assigned to this attachment.
         * 
         * @return builder
         * 
         */
        public Builder drgRouteTableId(@Nullable Output<String> drgRouteTableId) {
            $.drgRouteTableId = drgRouteTableId;
            return this;
        }

        /**
         * @param drgRouteTableId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG route table that is assigned to this attachment.
         * 
         * @return builder
         * 
         */
        public Builder drgRouteTableId(String drgRouteTableId) {
            return drgRouteTableId(Output.of(drgRouteTableId));
        }

        /**
         * @param exportDrgRouteDistributionId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the export route distribution used to specify how routes in the assigned DRG route table are advertised to the attachment. If this value is null, no routes are advertised through this attachment.
         * This field cannot be set by the user while creating the resource and gets a default value on creation. This can be only be updated to its default value. If this fields needs to be set to null, remove_export_drg_route_distribution_trigger needs to be used.
         * 
         * @return builder
         * 
         */
        public Builder exportDrgRouteDistributionId(@Nullable Output<String> exportDrgRouteDistributionId) {
            $.exportDrgRouteDistributionId = exportDrgRouteDistributionId;
            return this;
        }

        /**
         * @param exportDrgRouteDistributionId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the export route distribution used to specify how routes in the assigned DRG route table are advertised to the attachment. If this value is null, no routes are advertised through this attachment.
         * This field cannot be set by the user while creating the resource and gets a default value on creation. This can be only be updated to its default value. If this fields needs to be set to null, remove_export_drg_route_distribution_trigger needs to be used.
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
         * @param isCrossTenancy Indicates whether the DRG attachment and attached network live in a different tenancy than the DRG.  Example: `false`
         * 
         * @return builder
         * 
         */
        public Builder isCrossTenancy(@Nullable Output<Boolean> isCrossTenancy) {
            $.isCrossTenancy = isCrossTenancy;
            return this;
        }

        /**
         * @param isCrossTenancy Indicates whether the DRG attachment and attached network live in a different tenancy than the DRG.  Example: `false`
         * 
         * @return builder
         * 
         */
        public Builder isCrossTenancy(Boolean isCrossTenancy) {
            return isCrossTenancy(Output.of(isCrossTenancy));
        }

        /**
         * @param networkDetails (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder networkDetails(@Nullable Output<DrgAttachmentNetworkDetailsArgs> networkDetails) {
            $.networkDetails = networkDetails;
            return this;
        }

        /**
         * @param networkDetails (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder networkDetails(DrgAttachmentNetworkDetailsArgs networkDetails) {
            return networkDetails(Output.of(networkDetails));
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
         * @param routeTableId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table used by the DRG attachment.
         * 
         * @return builder
         * 
         */
        public Builder routeTableId(@Nullable Output<String> routeTableId) {
            $.routeTableId = routeTableId;
            return this;
        }

        /**
         * @param routeTableId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table used by the DRG attachment.
         * 
         * @return builder
         * 
         */
        public Builder routeTableId(String routeTableId) {
            return routeTableId(Output.of(routeTableId));
        }

        /**
         * @param state The DRG attachment&#39;s current state.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The DRG attachment&#39;s current state.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param timeCreated The date and time the DRG attachment was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time the DRG attachment was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param vcnId (Optional) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN. This field is deprecated. Instead, use the `networkDetails` field to specify the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the attached resource.
         * 
         * @return builder
         * 
         */
        public Builder vcnId(@Nullable Output<String> vcnId) {
            $.vcnId = vcnId;
            return this;
        }

        /**
         * @param vcnId (Optional) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN. This field is deprecated. Instead, use the `networkDetails` field to specify the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the attached resource.
         * 
         * @return builder
         * 
         */
        public Builder vcnId(String vcnId) {
            return vcnId(Output.of(vcnId));
        }

        public DrgAttachmentState build() {
            return $;
        }
    }

}