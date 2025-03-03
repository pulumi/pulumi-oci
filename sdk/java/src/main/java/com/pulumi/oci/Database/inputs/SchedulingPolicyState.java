// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Database.inputs.SchedulingPolicyCadenceStartMonthArgs;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class SchedulingPolicyState extends com.pulumi.resources.ResourceArgs {

    public static final SchedulingPolicyState Empty = new SchedulingPolicyState();

    /**
     * (Updatable) The cadence period.
     * 
     */
    @Import(name="cadence")
    private @Nullable Output<String> cadence;

    /**
     * @return (Updatable) The cadence period.
     * 
     */
    public Optional<Output<String>> cadence() {
        return Optional.ofNullable(this.cadence);
    }

    /**
     * (Updatable) Start of the month to be followed during the cadence period.
     * 
     */
    @Import(name="cadenceStartMonth")
    private @Nullable Output<SchedulingPolicyCadenceStartMonthArgs> cadenceStartMonth;

    /**
     * @return (Updatable) Start of the month to be followed during the cadence period.
     * 
     */
    public Optional<Output<SchedulingPolicyCadenceStartMonthArgs>> cadenceStartMonth() {
        return Optional.ofNullable(this.cadenceStartMonth);
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) The user-friendly name for the Scheduling Policy. The name does not need to be unique.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) The user-friendly name for the Scheduling Policy. The name does not need to be unique.
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
     * Additional information about the current lifecycle state.
     * 
     */
    @Import(name="lifecycleDetails")
    private @Nullable Output<String> lifecycleDetails;

    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    public Optional<Output<String>> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }

    /**
     * The current state of the Scheduling Policy. Valid states are CREATING, NEEDS_ATTENTION, ACTIVE, UPDATING, FAILED, DELETING and DELETED.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current state of the Scheduling Policy. Valid states are CREATING, NEEDS_ATTENTION, ACTIVE, UPDATING, FAILED, DELETING and DELETED.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The date and time the Scheduling Policy was created.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time the Scheduling Policy was created.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The date and time of the next scheduling window associated with the schedulingPolicy is planned to start.
     * 
     */
    @Import(name="timeNextWindowStarts")
    private @Nullable Output<String> timeNextWindowStarts;

    /**
     * @return The date and time of the next scheduling window associated with the schedulingPolicy is planned to start.
     * 
     */
    public Optional<Output<String>> timeNextWindowStarts() {
        return Optional.ofNullable(this.timeNextWindowStarts);
    }

    /**
     * The last date and time that the Scheduling Policy was updated.
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The last date and time that the Scheduling Policy was updated.
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    private SchedulingPolicyState() {}

    private SchedulingPolicyState(SchedulingPolicyState $) {
        this.cadence = $.cadence;
        this.cadenceStartMonth = $.cadenceStartMonth;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.lifecycleDetails = $.lifecycleDetails;
        this.state = $.state;
        this.timeCreated = $.timeCreated;
        this.timeNextWindowStarts = $.timeNextWindowStarts;
        this.timeUpdated = $.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(SchedulingPolicyState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private SchedulingPolicyState $;

        public Builder() {
            $ = new SchedulingPolicyState();
        }

        public Builder(SchedulingPolicyState defaults) {
            $ = new SchedulingPolicyState(Objects.requireNonNull(defaults));
        }

        /**
         * @param cadence (Updatable) The cadence period.
         * 
         * @return builder
         * 
         */
        public Builder cadence(@Nullable Output<String> cadence) {
            $.cadence = cadence;
            return this;
        }

        /**
         * @param cadence (Updatable) The cadence period.
         * 
         * @return builder
         * 
         */
        public Builder cadence(String cadence) {
            return cadence(Output.of(cadence));
        }

        /**
         * @param cadenceStartMonth (Updatable) Start of the month to be followed during the cadence period.
         * 
         * @return builder
         * 
         */
        public Builder cadenceStartMonth(@Nullable Output<SchedulingPolicyCadenceStartMonthArgs> cadenceStartMonth) {
            $.cadenceStartMonth = cadenceStartMonth;
            return this;
        }

        /**
         * @param cadenceStartMonth (Updatable) Start of the month to be followed during the cadence period.
         * 
         * @return builder
         * 
         */
        public Builder cadenceStartMonth(SchedulingPolicyCadenceStartMonthArgs cadenceStartMonth) {
            return cadenceStartMonth(Output.of(cadenceStartMonth));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName (Updatable) The user-friendly name for the Scheduling Policy. The name does not need to be unique.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) The user-friendly name for the Scheduling Policy. The name does not need to be unique.
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
         * @param lifecycleDetails Additional information about the current lifecycle state.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(@Nullable Output<String> lifecycleDetails) {
            $.lifecycleDetails = lifecycleDetails;
            return this;
        }

        /**
         * @param lifecycleDetails Additional information about the current lifecycle state.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(String lifecycleDetails) {
            return lifecycleDetails(Output.of(lifecycleDetails));
        }

        /**
         * @param state The current state of the Scheduling Policy. Valid states are CREATING, NEEDS_ATTENTION, ACTIVE, UPDATING, FAILED, DELETING and DELETED.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current state of the Scheduling Policy. Valid states are CREATING, NEEDS_ATTENTION, ACTIVE, UPDATING, FAILED, DELETING and DELETED.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param timeCreated The date and time the Scheduling Policy was created.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time the Scheduling Policy was created.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeNextWindowStarts The date and time of the next scheduling window associated with the schedulingPolicy is planned to start.
         * 
         * @return builder
         * 
         */
        public Builder timeNextWindowStarts(@Nullable Output<String> timeNextWindowStarts) {
            $.timeNextWindowStarts = timeNextWindowStarts;
            return this;
        }

        /**
         * @param timeNextWindowStarts The date and time of the next scheduling window associated with the schedulingPolicy is planned to start.
         * 
         * @return builder
         * 
         */
        public Builder timeNextWindowStarts(String timeNextWindowStarts) {
            return timeNextWindowStarts(Output.of(timeNextWindowStarts));
        }

        /**
         * @param timeUpdated The last date and time that the Scheduling Policy was updated.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The last date and time that the Scheduling Policy was updated.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        public SchedulingPolicyState build() {
            return $;
        }
    }

}
