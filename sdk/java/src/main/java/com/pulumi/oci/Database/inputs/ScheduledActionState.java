// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Database.inputs.ScheduledActionActionMemberArgs;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ScheduledActionState extends com.pulumi.resources.ResourceArgs {

    public static final ScheduledActionState Empty = new ScheduledActionState();

    /**
     * (Updatable) The list of action members in a scheduled action.
     * 
     */
    @Import(name="actionMembers")
    private @Nullable Output<List<ScheduledActionActionMemberArgs>> actionMembers;

    /**
     * @return (Updatable) The list of action members in a scheduled action.
     * 
     */
    public Optional<Output<List<ScheduledActionActionMemberArgs>>> actionMembers() {
        return Optional.ofNullable(this.actionMembers);
    }

    /**
     * The order of the scheduled action.
     * 
     */
    @Import(name="actionOrder")
    private @Nullable Output<Integer> actionOrder;

    /**
     * @return The order of the scheduled action.
     * 
     */
    public Optional<Output<Integer>> actionOrder() {
        return Optional.ofNullable(this.actionOrder);
    }

    /**
     * (Updatable) Map&lt;ParamName, ParamValue&gt; where a key value pair describes the specific action parameter. Example: `{&#34;count&#34;: &#34;3&#34;}`
     * 
     */
    @Import(name="actionParams")
    private @Nullable Output<Map<String,String>> actionParams;

    /**
     * @return (Updatable) Map&lt;ParamName, ParamValue&gt; where a key value pair describes the specific action parameter. Example: `{&#34;count&#34;: &#34;3&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> actionParams() {
        return Optional.ofNullable(this.actionParams);
    }

    /**
     * The type of the scheduled action being performed
     * 
     */
    @Import(name="actionType")
    private @Nullable Output<String> actionType;

    /**
     * @return The type of the scheduled action being performed
     * 
     */
    public Optional<Output<String>> actionType() {
        return Optional.ofNullable(this.actionType);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * The display name of the Scheduled Action.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return The display name of the Scheduled Action.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * The estimated patching time for the scheduled action.
     * 
     */
    @Import(name="estimatedTimeInMins")
    private @Nullable Output<Integer> estimatedTimeInMins;

    /**
     * @return The estimated patching time for the scheduled action.
     * 
     */
    public Optional<Output<Integer>> estimatedTimeInMins() {
        return Optional.ofNullable(this.estimatedTimeInMins);
    }

    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Scheduling Plan.
     * 
     */
    @Import(name="schedulingPlanId")
    private @Nullable Output<String> schedulingPlanId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Scheduling Plan.
     * 
     */
    public Optional<Output<String>> schedulingPlanId() {
        return Optional.ofNullable(this.schedulingPlanId);
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Scheduling Window.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="schedulingWindowId")
    private @Nullable Output<String> schedulingWindowId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Scheduling Window.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> schedulingWindowId() {
        return Optional.ofNullable(this.schedulingWindowId);
    }

    /**
     * The current state of the Scheduled Action. Valid states are CREATING, NEEDS_ATTENTION, AVAILABLE, UPDATING, FAILED, DELETING and DELETED.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current state of the Scheduled Action. Valid states are CREATING, NEEDS_ATTENTION, AVAILABLE, UPDATING, FAILED, DELETING and DELETED.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    @Import(name="systemTags")
    private @Nullable Output<Map<String,String>> systemTags;

    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Optional<Output<Map<String,String>>> systemTags() {
        return Optional.ofNullable(this.systemTags);
    }

    /**
     * The date and time the Scheduled Action Resource was created.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time the Scheduled Action Resource was created.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The date and time the Scheduled Action Resource was updated.
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The date and time the Scheduled Action Resource was updated.
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    private ScheduledActionState() {}

    private ScheduledActionState(ScheduledActionState $) {
        this.actionMembers = $.actionMembers;
        this.actionOrder = $.actionOrder;
        this.actionParams = $.actionParams;
        this.actionType = $.actionType;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.estimatedTimeInMins = $.estimatedTimeInMins;
        this.freeformTags = $.freeformTags;
        this.schedulingPlanId = $.schedulingPlanId;
        this.schedulingWindowId = $.schedulingWindowId;
        this.state = $.state;
        this.systemTags = $.systemTags;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ScheduledActionState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ScheduledActionState $;

        public Builder() {
            $ = new ScheduledActionState();
        }

        public Builder(ScheduledActionState defaults) {
            $ = new ScheduledActionState(Objects.requireNonNull(defaults));
        }

        /**
         * @param actionMembers (Updatable) The list of action members in a scheduled action.
         * 
         * @return builder
         * 
         */
        public Builder actionMembers(@Nullable Output<List<ScheduledActionActionMemberArgs>> actionMembers) {
            $.actionMembers = actionMembers;
            return this;
        }

        /**
         * @param actionMembers (Updatable) The list of action members in a scheduled action.
         * 
         * @return builder
         * 
         */
        public Builder actionMembers(List<ScheduledActionActionMemberArgs> actionMembers) {
            return actionMembers(Output.of(actionMembers));
        }

        /**
         * @param actionMembers (Updatable) The list of action members in a scheduled action.
         * 
         * @return builder
         * 
         */
        public Builder actionMembers(ScheduledActionActionMemberArgs... actionMembers) {
            return actionMembers(List.of(actionMembers));
        }

        /**
         * @param actionOrder The order of the scheduled action.
         * 
         * @return builder
         * 
         */
        public Builder actionOrder(@Nullable Output<Integer> actionOrder) {
            $.actionOrder = actionOrder;
            return this;
        }

        /**
         * @param actionOrder The order of the scheduled action.
         * 
         * @return builder
         * 
         */
        public Builder actionOrder(Integer actionOrder) {
            return actionOrder(Output.of(actionOrder));
        }

        /**
         * @param actionParams (Updatable) Map&lt;ParamName, ParamValue&gt; where a key value pair describes the specific action parameter. Example: `{&#34;count&#34;: &#34;3&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder actionParams(@Nullable Output<Map<String,String>> actionParams) {
            $.actionParams = actionParams;
            return this;
        }

        /**
         * @param actionParams (Updatable) Map&lt;ParamName, ParamValue&gt; where a key value pair describes the specific action parameter. Example: `{&#34;count&#34;: &#34;3&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder actionParams(Map<String,String> actionParams) {
            return actionParams(Output.of(actionParams));
        }

        /**
         * @param actionType The type of the scheduled action being performed
         * 
         * @return builder
         * 
         */
        public Builder actionType(@Nullable Output<String> actionType) {
            $.actionType = actionType;
            return this;
        }

        /**
         * @param actionType The type of the scheduled action being performed
         * 
         * @return builder
         * 
         */
        public Builder actionType(String actionType) {
            return actionType(Output.of(actionType));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
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
         * @param definedTags Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName The display name of the Scheduled Action.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName The display name of the Scheduled Action.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param estimatedTimeInMins The estimated patching time for the scheduled action.
         * 
         * @return builder
         * 
         */
        public Builder estimatedTimeInMins(@Nullable Output<Integer> estimatedTimeInMins) {
            $.estimatedTimeInMins = estimatedTimeInMins;
            return this;
        }

        /**
         * @param estimatedTimeInMins The estimated patching time for the scheduled action.
         * 
         * @return builder
         * 
         */
        public Builder estimatedTimeInMins(Integer estimatedTimeInMins) {
            return estimatedTimeInMins(Output.of(estimatedTimeInMins));
        }

        /**
         * @param freeformTags Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param schedulingPlanId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Scheduling Plan.
         * 
         * @return builder
         * 
         */
        public Builder schedulingPlanId(@Nullable Output<String> schedulingPlanId) {
            $.schedulingPlanId = schedulingPlanId;
            return this;
        }

        /**
         * @param schedulingPlanId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Scheduling Plan.
         * 
         * @return builder
         * 
         */
        public Builder schedulingPlanId(String schedulingPlanId) {
            return schedulingPlanId(Output.of(schedulingPlanId));
        }

        /**
         * @param schedulingWindowId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Scheduling Window.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder schedulingWindowId(@Nullable Output<String> schedulingWindowId) {
            $.schedulingWindowId = schedulingWindowId;
            return this;
        }

        /**
         * @param schedulingWindowId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Scheduling Window.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder schedulingWindowId(String schedulingWindowId) {
            return schedulingWindowId(Output.of(schedulingWindowId));
        }

        /**
         * @param state The current state of the Scheduled Action. Valid states are CREATING, NEEDS_ATTENTION, AVAILABLE, UPDATING, FAILED, DELETING and DELETED.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current state of the Scheduled Action. Valid states are CREATING, NEEDS_ATTENTION, AVAILABLE, UPDATING, FAILED, DELETING and DELETED.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param systemTags System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
         * 
         * @return builder
         * 
         */
        public Builder systemTags(@Nullable Output<Map<String,String>> systemTags) {
            $.systemTags = systemTags;
            return this;
        }

        /**
         * @param systemTags System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
         * 
         * @return builder
         * 
         */
        public Builder systemTags(Map<String,String> systemTags) {
            return systemTags(Output.of(systemTags));
        }

        /**
         * @param timeCreated The date and time the Scheduled Action Resource was created.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time the Scheduled Action Resource was created.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated The date and time the Scheduled Action Resource was updated.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The date and time the Scheduled Action Resource was updated.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        public ScheduledActionState build() {
            return $;
        }
    }

}
