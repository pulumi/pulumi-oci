// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ExecutionWindowState extends com.pulumi.resources.ResourceArgs {

    public static final ExecutionWindowState Empty = new ExecutionWindowState();

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
     * Description of the execution window.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return Description of the execution window.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * The user-friendly name for the execution window. The name does not need to be unique.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return The user-friendly name for the execution window. The name does not need to be unique.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * The estimated time of the execution window in minutes.
     * 
     */
    @Import(name="estimatedTimeInMins")
    private @Nullable Output<Integer> estimatedTimeInMins;

    /**
     * @return The estimated time of the execution window in minutes.
     * 
     */
    public Optional<Output<Integer>> estimatedTimeInMins() {
        return Optional.ofNullable(this.estimatedTimeInMins);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the execution resource the execution window belongs to.
     * 
     */
    @Import(name="executionResourceId")
    private @Nullable Output<String> executionResourceId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the execution resource the execution window belongs to.
     * 
     */
    public Optional<Output<String>> executionResourceId() {
        return Optional.ofNullable(this.executionResourceId);
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) Indicates if duration the user plans to allocate for scheduling window is strictly enforced. The default value is `FALSE`.
     * 
     */
    @Import(name="isEnforcedDuration")
    private @Nullable Output<Boolean> isEnforcedDuration;

    /**
     * @return (Updatable) Indicates if duration the user plans to allocate for scheduling window is strictly enforced. The default value is `FALSE`.
     * 
     */
    public Optional<Output<Boolean>> isEnforcedDuration() {
        return Optional.ofNullable(this.isEnforcedDuration);
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
     * The current sub-state of the execution window. Valid states are DURATION_EXCEEDED, MAINTENANCE_IN_PROGRESS and WAITING.
     * 
     */
    @Import(name="lifecycleSubstate")
    private @Nullable Output<String> lifecycleSubstate;

    /**
     * @return The current sub-state of the execution window. Valid states are DURATION_EXCEEDED, MAINTENANCE_IN_PROGRESS and WAITING.
     * 
     */
    public Optional<Output<String>> lifecycleSubstate() {
        return Optional.ofNullable(this.lifecycleSubstate);
    }

    /**
     * The current state of the Schedule Policy. Valid states are CREATED, SCHEDULED, IN_PROGRESS, FAILED, CANCELED, UPDATING, DELETED, SUCCEEDED and PARTIAL_SUCCESS.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current state of the Schedule Policy. Valid states are CREATED, SCHEDULED, IN_PROGRESS, FAILED, CANCELED, UPDATING, DELETED, SUCCEEDED and PARTIAL_SUCCESS.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The date and time the execution window was created.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time the execution window was created.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The date and time that the execution window ended.
     * 
     */
    @Import(name="timeEnded")
    private @Nullable Output<String> timeEnded;

    /**
     * @return The date and time that the execution window ended.
     * 
     */
    public Optional<Output<String>> timeEnded() {
        return Optional.ofNullable(this.timeEnded);
    }

    /**
     * (Updatable) The scheduled start date and time of the execution window.
     * 
     */
    @Import(name="timeScheduled")
    private @Nullable Output<String> timeScheduled;

    /**
     * @return (Updatable) The scheduled start date and time of the execution window.
     * 
     */
    public Optional<Output<String>> timeScheduled() {
        return Optional.ofNullable(this.timeScheduled);
    }

    /**
     * The date and time that the execution window was started.
     * 
     */
    @Import(name="timeStarted")
    private @Nullable Output<String> timeStarted;

    /**
     * @return The date and time that the execution window was started.
     * 
     */
    public Optional<Output<String>> timeStarted() {
        return Optional.ofNullable(this.timeStarted);
    }

    /**
     * The last date and time that the execution window was updated.
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The last date and time that the execution window was updated.
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    /**
     * The total time taken by corresponding resource activity in minutes.
     * 
     */
    @Import(name="totalTimeTakenInMins")
    private @Nullable Output<Integer> totalTimeTakenInMins;

    /**
     * @return The total time taken by corresponding resource activity in minutes.
     * 
     */
    public Optional<Output<Integer>> totalTimeTakenInMins() {
        return Optional.ofNullable(this.totalTimeTakenInMins);
    }

    /**
     * (Updatable) Duration window allows user to set a duration they plan to allocate for Scheduling window. The duration is in minutes.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="windowDurationInMins")
    private @Nullable Output<Integer> windowDurationInMins;

    /**
     * @return (Updatable) Duration window allows user to set a duration they plan to allocate for Scheduling window. The duration is in minutes.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<Integer>> windowDurationInMins() {
        return Optional.ofNullable(this.windowDurationInMins);
    }

    /**
     * The execution window is of PLANNED or UNPLANNED type.
     * 
     */
    @Import(name="windowType")
    private @Nullable Output<String> windowType;

    /**
     * @return The execution window is of PLANNED or UNPLANNED type.
     * 
     */
    public Optional<Output<String>> windowType() {
        return Optional.ofNullable(this.windowType);
    }

    private ExecutionWindowState() {}

    private ExecutionWindowState(ExecutionWindowState $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.displayName = $.displayName;
        this.estimatedTimeInMins = $.estimatedTimeInMins;
        this.executionResourceId = $.executionResourceId;
        this.freeformTags = $.freeformTags;
        this.isEnforcedDuration = $.isEnforcedDuration;
        this.lifecycleDetails = $.lifecycleDetails;
        this.lifecycleSubstate = $.lifecycleSubstate;
        this.state = $.state;
        this.timeCreated = $.timeCreated;
        this.timeEnded = $.timeEnded;
        this.timeScheduled = $.timeScheduled;
        this.timeStarted = $.timeStarted;
        this.timeUpdated = $.timeUpdated;
        this.totalTimeTakenInMins = $.totalTimeTakenInMins;
        this.windowDurationInMins = $.windowDurationInMins;
        this.windowType = $.windowType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ExecutionWindowState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ExecutionWindowState $;

        public Builder() {
            $ = new ExecutionWindowState();
        }

        public Builder(ExecutionWindowState defaults) {
            $ = new ExecutionWindowState(Objects.requireNonNull(defaults));
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
         * @param description Description of the execution window.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description Description of the execution window.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName The user-friendly name for the execution window. The name does not need to be unique.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName The user-friendly name for the execution window. The name does not need to be unique.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param estimatedTimeInMins The estimated time of the execution window in minutes.
         * 
         * @return builder
         * 
         */
        public Builder estimatedTimeInMins(@Nullable Output<Integer> estimatedTimeInMins) {
            $.estimatedTimeInMins = estimatedTimeInMins;
            return this;
        }

        /**
         * @param estimatedTimeInMins The estimated time of the execution window in minutes.
         * 
         * @return builder
         * 
         */
        public Builder estimatedTimeInMins(Integer estimatedTimeInMins) {
            return estimatedTimeInMins(Output.of(estimatedTimeInMins));
        }

        /**
         * @param executionResourceId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the execution resource the execution window belongs to.
         * 
         * @return builder
         * 
         */
        public Builder executionResourceId(@Nullable Output<String> executionResourceId) {
            $.executionResourceId = executionResourceId;
            return this;
        }

        /**
         * @param executionResourceId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the execution resource the execution window belongs to.
         * 
         * @return builder
         * 
         */
        public Builder executionResourceId(String executionResourceId) {
            return executionResourceId(Output.of(executionResourceId));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
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
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param isEnforcedDuration (Updatable) Indicates if duration the user plans to allocate for scheduling window is strictly enforced. The default value is `FALSE`.
         * 
         * @return builder
         * 
         */
        public Builder isEnforcedDuration(@Nullable Output<Boolean> isEnforcedDuration) {
            $.isEnforcedDuration = isEnforcedDuration;
            return this;
        }

        /**
         * @param isEnforcedDuration (Updatable) Indicates if duration the user plans to allocate for scheduling window is strictly enforced. The default value is `FALSE`.
         * 
         * @return builder
         * 
         */
        public Builder isEnforcedDuration(Boolean isEnforcedDuration) {
            return isEnforcedDuration(Output.of(isEnforcedDuration));
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
         * @param lifecycleSubstate The current sub-state of the execution window. Valid states are DURATION_EXCEEDED, MAINTENANCE_IN_PROGRESS and WAITING.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleSubstate(@Nullable Output<String> lifecycleSubstate) {
            $.lifecycleSubstate = lifecycleSubstate;
            return this;
        }

        /**
         * @param lifecycleSubstate The current sub-state of the execution window. Valid states are DURATION_EXCEEDED, MAINTENANCE_IN_PROGRESS and WAITING.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleSubstate(String lifecycleSubstate) {
            return lifecycleSubstate(Output.of(lifecycleSubstate));
        }

        /**
         * @param state The current state of the Schedule Policy. Valid states are CREATED, SCHEDULED, IN_PROGRESS, FAILED, CANCELED, UPDATING, DELETED, SUCCEEDED and PARTIAL_SUCCESS.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current state of the Schedule Policy. Valid states are CREATED, SCHEDULED, IN_PROGRESS, FAILED, CANCELED, UPDATING, DELETED, SUCCEEDED and PARTIAL_SUCCESS.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param timeCreated The date and time the execution window was created.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time the execution window was created.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeEnded The date and time that the execution window ended.
         * 
         * @return builder
         * 
         */
        public Builder timeEnded(@Nullable Output<String> timeEnded) {
            $.timeEnded = timeEnded;
            return this;
        }

        /**
         * @param timeEnded The date and time that the execution window ended.
         * 
         * @return builder
         * 
         */
        public Builder timeEnded(String timeEnded) {
            return timeEnded(Output.of(timeEnded));
        }

        /**
         * @param timeScheduled (Updatable) The scheduled start date and time of the execution window.
         * 
         * @return builder
         * 
         */
        public Builder timeScheduled(@Nullable Output<String> timeScheduled) {
            $.timeScheduled = timeScheduled;
            return this;
        }

        /**
         * @param timeScheduled (Updatable) The scheduled start date and time of the execution window.
         * 
         * @return builder
         * 
         */
        public Builder timeScheduled(String timeScheduled) {
            return timeScheduled(Output.of(timeScheduled));
        }

        /**
         * @param timeStarted The date and time that the execution window was started.
         * 
         * @return builder
         * 
         */
        public Builder timeStarted(@Nullable Output<String> timeStarted) {
            $.timeStarted = timeStarted;
            return this;
        }

        /**
         * @param timeStarted The date and time that the execution window was started.
         * 
         * @return builder
         * 
         */
        public Builder timeStarted(String timeStarted) {
            return timeStarted(Output.of(timeStarted));
        }

        /**
         * @param timeUpdated The last date and time that the execution window was updated.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The last date and time that the execution window was updated.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        /**
         * @param totalTimeTakenInMins The total time taken by corresponding resource activity in minutes.
         * 
         * @return builder
         * 
         */
        public Builder totalTimeTakenInMins(@Nullable Output<Integer> totalTimeTakenInMins) {
            $.totalTimeTakenInMins = totalTimeTakenInMins;
            return this;
        }

        /**
         * @param totalTimeTakenInMins The total time taken by corresponding resource activity in minutes.
         * 
         * @return builder
         * 
         */
        public Builder totalTimeTakenInMins(Integer totalTimeTakenInMins) {
            return totalTimeTakenInMins(Output.of(totalTimeTakenInMins));
        }

        /**
         * @param windowDurationInMins (Updatable) Duration window allows user to set a duration they plan to allocate for Scheduling window. The duration is in minutes.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder windowDurationInMins(@Nullable Output<Integer> windowDurationInMins) {
            $.windowDurationInMins = windowDurationInMins;
            return this;
        }

        /**
         * @param windowDurationInMins (Updatable) Duration window allows user to set a duration they plan to allocate for Scheduling window. The duration is in minutes.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder windowDurationInMins(Integer windowDurationInMins) {
            return windowDurationInMins(Output.of(windowDurationInMins));
        }

        /**
         * @param windowType The execution window is of PLANNED or UNPLANNED type.
         * 
         * @return builder
         * 
         */
        public Builder windowType(@Nullable Output<String> windowType) {
            $.windowType = windowType;
            return this;
        }

        /**
         * @param windowType The execution window is of PLANNED or UNPLANNED type.
         * 
         * @return builder
         * 
         */
        public Builder windowType(String windowType) {
            return windowType(Output.of(windowType));
        }

        public ExecutionWindowState build() {
            return $;
        }
    }

}
