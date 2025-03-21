// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Core.inputs.DrgDefaultDrgRouteTableArgs;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DrgState extends com.pulumi.resources.ResourceArgs {

    public static final DrgState Empty = new DrgState();

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the DRG.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the DRG.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * The default DRG route table for this DRG. Each network type has a default DRG route table.
     * 
     */
    @Import(name="defaultDrgRouteTables")
    private @Nullable Output<List<DrgDefaultDrgRouteTableArgs>> defaultDrgRouteTables;

    /**
     * @return The default DRG route table for this DRG. Each network type has a default DRG route table.
     * 
     */
    public Optional<Output<List<DrgDefaultDrgRouteTableArgs>>> defaultDrgRouteTables() {
        return Optional.ofNullable(this.defaultDrgRouteTables);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this DRG&#39;s default export route distribution for the DRG attachments.
     * 
     */
    @Import(name="defaultExportDrgRouteDistributionId")
    private @Nullable Output<String> defaultExportDrgRouteDistributionId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this DRG&#39;s default export route distribution for the DRG attachments.
     * 
     */
    public Optional<Output<String>> defaultExportDrgRouteDistributionId() {
        return Optional.ofNullable(this.defaultExportDrgRouteDistributionId);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
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
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * The redundancy status of the DRG specified.
     * 
     */
    @Import(name="redundancyStatus")
    private @Nullable Output<String> redundancyStatus;

    /**
     * @return The redundancy status of the DRG specified.
     * 
     */
    public Optional<Output<String>> redundancyStatus() {
        return Optional.ofNullable(this.redundancyStatus);
    }

    /**
     * The DRG&#39;s current state.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The DRG&#39;s current state.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The date and time the DRG was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time the DRG was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    private DrgState() {}

    private DrgState(DrgState $) {
        this.compartmentId = $.compartmentId;
        this.defaultDrgRouteTables = $.defaultDrgRouteTables;
        this.defaultExportDrgRouteDistributionId = $.defaultExportDrgRouteDistributionId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.redundancyStatus = $.redundancyStatus;
        this.state = $.state;
        this.timeCreated = $.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DrgState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DrgState $;

        public Builder() {
            $ = new DrgState();
        }

        public Builder(DrgState defaults) {
            $ = new DrgState(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the DRG.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the DRG.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param defaultDrgRouteTables The default DRG route table for this DRG. Each network type has a default DRG route table.
         * 
         * @return builder
         * 
         */
        public Builder defaultDrgRouteTables(@Nullable Output<List<DrgDefaultDrgRouteTableArgs>> defaultDrgRouteTables) {
            $.defaultDrgRouteTables = defaultDrgRouteTables;
            return this;
        }

        /**
         * @param defaultDrgRouteTables The default DRG route table for this DRG. Each network type has a default DRG route table.
         * 
         * @return builder
         * 
         */
        public Builder defaultDrgRouteTables(List<DrgDefaultDrgRouteTableArgs> defaultDrgRouteTables) {
            return defaultDrgRouteTables(Output.of(defaultDrgRouteTables));
        }

        /**
         * @param defaultDrgRouteTables The default DRG route table for this DRG. Each network type has a default DRG route table.
         * 
         * @return builder
         * 
         */
        public Builder defaultDrgRouteTables(DrgDefaultDrgRouteTableArgs... defaultDrgRouteTables) {
            return defaultDrgRouteTables(List.of(defaultDrgRouteTables));
        }

        /**
         * @param defaultExportDrgRouteDistributionId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this DRG&#39;s default export route distribution for the DRG attachments.
         * 
         * @return builder
         * 
         */
        public Builder defaultExportDrgRouteDistributionId(@Nullable Output<String> defaultExportDrgRouteDistributionId) {
            $.defaultExportDrgRouteDistributionId = defaultExportDrgRouteDistributionId;
            return this;
        }

        /**
         * @param defaultExportDrgRouteDistributionId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this DRG&#39;s default export route distribution for the DRG attachments.
         * 
         * @return builder
         * 
         */
        public Builder defaultExportDrgRouteDistributionId(String defaultExportDrgRouteDistributionId) {
            return defaultExportDrgRouteDistributionId(Output.of(defaultExportDrgRouteDistributionId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
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
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param redundancyStatus The redundancy status of the DRG specified.
         * 
         * @return builder
         * 
         */
        public Builder redundancyStatus(@Nullable Output<String> redundancyStatus) {
            $.redundancyStatus = redundancyStatus;
            return this;
        }

        /**
         * @param redundancyStatus The redundancy status of the DRG specified.
         * 
         * @return builder
         * 
         */
        public Builder redundancyStatus(String redundancyStatus) {
            return redundancyStatus(Output.of(redundancyStatus));
        }

        /**
         * @param state The DRG&#39;s current state.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The DRG&#39;s current state.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param timeCreated The date and time the DRG was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time the DRG was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        public DrgState build() {
            return $;
        }
    }

}
