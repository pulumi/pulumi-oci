// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DrgRouteTableState extends com.pulumi.resources.ResourceArgs {

    public static final DrgRouteTableState Empty = new DrgRouteTableState();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment the DRG is in. The DRG route table is always in the same compartment as the DRG.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment the DRG is in. The DRG route table is always in the same compartment as the DRG.
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
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG the DRG route table belongs to.
     * 
     */
    @Import(name="drgId")
    private @Nullable Output<String> drgId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG the DRG route table belongs to.
     * 
     */
    public Optional<Output<String>> drgId() {
        return Optional.ofNullable(this.drgId);
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
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the import route distribution used to specify how incoming route advertisements through referenced attachments are inserted into the DRG route table.
     * 
     */
    @Import(name="importDrgRouteDistributionId")
    private @Nullable Output<String> importDrgRouteDistributionId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the import route distribution used to specify how incoming route advertisements through referenced attachments are inserted into the DRG route table.
     * 
     */
    public Optional<Output<String>> importDrgRouteDistributionId() {
        return Optional.ofNullable(this.importDrgRouteDistributionId);
    }

    /**
     * (Updatable) If you want traffic to be routed using ECMP across your virtual circuits or IPSec tunnels to your on-premises networks, enable ECMP on the DRG route table.
     * 
     */
    @Import(name="isEcmpEnabled")
    private @Nullable Output<Boolean> isEcmpEnabled;

    /**
     * @return (Updatable) If you want traffic to be routed using ECMP across your virtual circuits or IPSec tunnels to your on-premises networks, enable ECMP on the DRG route table.
     * 
     */
    public Optional<Output<Boolean>> isEcmpEnabled() {
        return Optional.ofNullable(this.isEcmpEnabled);
    }

    /**
     * (Updatable) An optional property when flipped disables the import of route Distribution by setting import_drg_route_distribution_id to null.
     * 
     */
    @Import(name="removeImportTrigger")
    private @Nullable Output<Boolean> removeImportTrigger;

    /**
     * @return (Updatable) An optional property when flipped disables the import of route Distribution by setting import_drg_route_distribution_id to null.
     * 
     */
    public Optional<Output<Boolean>> removeImportTrigger() {
        return Optional.ofNullable(this.removeImportTrigger);
    }

    /**
     * The DRG route table&#39;s current state.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The DRG route table&#39;s current state.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The date and time the DRG route table was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time the DRG route table was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    private DrgRouteTableState() {}

    private DrgRouteTableState(DrgRouteTableState $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.drgId = $.drgId;
        this.freeformTags = $.freeformTags;
        this.importDrgRouteDistributionId = $.importDrgRouteDistributionId;
        this.isEcmpEnabled = $.isEcmpEnabled;
        this.removeImportTrigger = $.removeImportTrigger;
        this.state = $.state;
        this.timeCreated = $.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DrgRouteTableState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DrgRouteTableState $;

        public Builder() {
            $ = new DrgRouteTableState();
        }

        public Builder(DrgRouteTableState defaults) {
            $ = new DrgRouteTableState(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment the DRG is in. The DRG route table is always in the same compartment as the DRG.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment the DRG is in. The DRG route table is always in the same compartment as the DRG.
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
         * @param drgId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG the DRG route table belongs to.
         * 
         * @return builder
         * 
         */
        public Builder drgId(@Nullable Output<String> drgId) {
            $.drgId = drgId;
            return this;
        }

        /**
         * @param drgId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG the DRG route table belongs to.
         * 
         * @return builder
         * 
         */
        public Builder drgId(String drgId) {
            return drgId(Output.of(drgId));
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
         * @param importDrgRouteDistributionId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the import route distribution used to specify how incoming route advertisements through referenced attachments are inserted into the DRG route table.
         * 
         * @return builder
         * 
         */
        public Builder importDrgRouteDistributionId(@Nullable Output<String> importDrgRouteDistributionId) {
            $.importDrgRouteDistributionId = importDrgRouteDistributionId;
            return this;
        }

        /**
         * @param importDrgRouteDistributionId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the import route distribution used to specify how incoming route advertisements through referenced attachments are inserted into the DRG route table.
         * 
         * @return builder
         * 
         */
        public Builder importDrgRouteDistributionId(String importDrgRouteDistributionId) {
            return importDrgRouteDistributionId(Output.of(importDrgRouteDistributionId));
        }

        /**
         * @param isEcmpEnabled (Updatable) If you want traffic to be routed using ECMP across your virtual circuits or IPSec tunnels to your on-premises networks, enable ECMP on the DRG route table.
         * 
         * @return builder
         * 
         */
        public Builder isEcmpEnabled(@Nullable Output<Boolean> isEcmpEnabled) {
            $.isEcmpEnabled = isEcmpEnabled;
            return this;
        }

        /**
         * @param isEcmpEnabled (Updatable) If you want traffic to be routed using ECMP across your virtual circuits or IPSec tunnels to your on-premises networks, enable ECMP on the DRG route table.
         * 
         * @return builder
         * 
         */
        public Builder isEcmpEnabled(Boolean isEcmpEnabled) {
            return isEcmpEnabled(Output.of(isEcmpEnabled));
        }

        /**
         * @param removeImportTrigger (Updatable) An optional property when flipped disables the import of route Distribution by setting import_drg_route_distribution_id to null.
         * 
         * @return builder
         * 
         */
        public Builder removeImportTrigger(@Nullable Output<Boolean> removeImportTrigger) {
            $.removeImportTrigger = removeImportTrigger;
            return this;
        }

        /**
         * @param removeImportTrigger (Updatable) An optional property when flipped disables the import of route Distribution by setting import_drg_route_distribution_id to null.
         * 
         * @return builder
         * 
         */
        public Builder removeImportTrigger(Boolean removeImportTrigger) {
            return removeImportTrigger(Output.of(removeImportTrigger));
        }

        /**
         * @param state The DRG route table&#39;s current state.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The DRG route table&#39;s current state.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param timeCreated The date and time the DRG route table was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time the DRG route table was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        public DrgRouteTableState build() {
            return $;
        }
    }

}