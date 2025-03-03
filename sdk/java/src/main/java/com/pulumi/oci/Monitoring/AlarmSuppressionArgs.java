// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Monitoring;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Monitoring.inputs.AlarmSuppressionAlarmSuppressionTargetArgs;
import com.pulumi.oci.Monitoring.inputs.AlarmSuppressionSuppressionConditionArgs;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class AlarmSuppressionArgs extends com.pulumi.resources.ResourceArgs {

    public static final AlarmSuppressionArgs Empty = new AlarmSuppressionArgs();

    /**
     * The target of the alarm suppression.
     * 
     */
    @Import(name="alarmSuppressionTarget", required=true)
    private Output<AlarmSuppressionAlarmSuppressionTargetArgs> alarmSuppressionTarget;

    /**
     * @return The target of the alarm suppression.
     * 
     */
    public Output<AlarmSuppressionAlarmSuppressionTargetArgs> alarmSuppressionTarget() {
        return this.alarmSuppressionTarget;
    }

    /**
     * Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * Human-readable reason for this alarm suppression. It does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     * Oracle recommends including tracking information for the event or associated work, such as a ticket number.
     * 
     * Example: `Planned outage due to change IT-1234.`
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return Human-readable reason for this alarm suppression. It does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     * Oracle recommends including tracking information for the event or associated work, such as a ticket number.
     * 
     * Example: `Planned outage due to change IT-1234.`
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * A filter to suppress only alarm state entries that include the set of specified dimension key-value pairs. If you specify {&#34;availabilityDomain&#34;: &#34;phx-ad-1&#34;} and the alarm state entry corresponds to the set {&#34;availabilityDomain&#34;: &#34;phx-ad-1&#34; and &#34;resourceId&#34;: &#34;instance.region1.phx.exampleuniqueID&#34;}, then this alarm will be included for suppression.
     * 
     * This is required only when the value of level is `DIMENSION`. If required, the value cannot be an empty object. Only a single value is allowed per key. No grouping of multiple values is allowed under the same key. Maximum characters (after serialization): 4000. This maximum satisfies typical use cases. The response for an exceeded maximum is `HTTP 400` with an &#34;dimensions values are too long&#34; message.
     * 
     */
    @Import(name="dimensions")
    private @Nullable Output<Map<String,String>> dimensions;

    /**
     * @return A filter to suppress only alarm state entries that include the set of specified dimension key-value pairs. If you specify {&#34;availabilityDomain&#34;: &#34;phx-ad-1&#34;} and the alarm state entry corresponds to the set {&#34;availabilityDomain&#34;: &#34;phx-ad-1&#34; and &#34;resourceId&#34;: &#34;instance.region1.phx.exampleuniqueID&#34;}, then this alarm will be included for suppression.
     * 
     * This is required only when the value of level is `DIMENSION`. If required, the value cannot be an empty object. Only a single value is allowed per key. No grouping of multiple values is allowed under the same key. Maximum characters (after serialization): 4000. This maximum satisfies typical use cases. The response for an exceeded maximum is `HTTP 400` with an &#34;dimensions values are too long&#34; message.
     * 
     */
    public Optional<Output<Map<String,String>>> dimensions() {
        return Optional.ofNullable(this.dimensions);
    }

    /**
     * A user-friendly name for the alarm suppression. It does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return A user-friendly name for the alarm suppression. It does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }

    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * The level of this alarm suppression. `ALARM` indicates a suppression of the entire alarm, regardless of dimension. `DIMENSION` indicates a suppression configured for specified dimensions.
     * 
     * Defaut: `DIMENSION`
     * 
     */
    @Import(name="level")
    private @Nullable Output<String> level;

    /**
     * @return The level of this alarm suppression. `ALARM` indicates a suppression of the entire alarm, regardless of dimension. `DIMENSION` indicates a suppression configured for specified dimensions.
     * 
     * Defaut: `DIMENSION`
     * 
     */
    public Optional<Output<String>> level() {
        return Optional.ofNullable(this.level);
    }

    /**
     * Array of all preconditions for alarm suppression. Example: `[{ conditionType: &#34;RECURRENCE&#34;, suppressionRecurrence: &#34;FRQ=DAILY;BYHOUR=10&#34;, suppressionDuration: &#34;PT1H&#34; }]`
     * 
     */
    @Import(name="suppressionConditions")
    private @Nullable Output<List<AlarmSuppressionSuppressionConditionArgs>> suppressionConditions;

    /**
     * @return Array of all preconditions for alarm suppression. Example: `[{ conditionType: &#34;RECURRENCE&#34;, suppressionRecurrence: &#34;FRQ=DAILY;BYHOUR=10&#34;, suppressionDuration: &#34;PT1H&#34; }]`
     * 
     */
    public Optional<Output<List<AlarmSuppressionSuppressionConditionArgs>>> suppressionConditions() {
        return Optional.ofNullable(this.suppressionConditions);
    }

    /**
     * The start date and time for the suppression to take place, inclusive. Format defined by RFC3339.  Example: `2023-02-01T01:02:29.600Z`
     * 
     */
    @Import(name="timeSuppressFrom", required=true)
    private Output<String> timeSuppressFrom;

    /**
     * @return The start date and time for the suppression to take place, inclusive. Format defined by RFC3339.  Example: `2023-02-01T01:02:29.600Z`
     * 
     */
    public Output<String> timeSuppressFrom() {
        return this.timeSuppressFrom;
    }

    /**
     * The end date and time for the suppression to take place, inclusive. Format defined by RFC3339.  Example: `2023-02-01T02:02:29.600Z`
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="timeSuppressUntil", required=true)
    private Output<String> timeSuppressUntil;

    /**
     * @return The end date and time for the suppression to take place, inclusive. Format defined by RFC3339.  Example: `2023-02-01T02:02:29.600Z`
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> timeSuppressUntil() {
        return this.timeSuppressUntil;
    }

    private AlarmSuppressionArgs() {}

    private AlarmSuppressionArgs(AlarmSuppressionArgs $) {
        this.alarmSuppressionTarget = $.alarmSuppressionTarget;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.dimensions = $.dimensions;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.level = $.level;
        this.suppressionConditions = $.suppressionConditions;
        this.timeSuppressFrom = $.timeSuppressFrom;
        this.timeSuppressUntil = $.timeSuppressUntil;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(AlarmSuppressionArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private AlarmSuppressionArgs $;

        public Builder() {
            $ = new AlarmSuppressionArgs();
        }

        public Builder(AlarmSuppressionArgs defaults) {
            $ = new AlarmSuppressionArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param alarmSuppressionTarget The target of the alarm suppression.
         * 
         * @return builder
         * 
         */
        public Builder alarmSuppressionTarget(Output<AlarmSuppressionAlarmSuppressionTargetArgs> alarmSuppressionTarget) {
            $.alarmSuppressionTarget = alarmSuppressionTarget;
            return this;
        }

        /**
         * @param alarmSuppressionTarget The target of the alarm suppression.
         * 
         * @return builder
         * 
         */
        public Builder alarmSuppressionTarget(AlarmSuppressionAlarmSuppressionTargetArgs alarmSuppressionTarget) {
            return alarmSuppressionTarget(Output.of(alarmSuppressionTarget));
        }

        /**
         * @param definedTags Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param description Human-readable reason for this alarm suppression. It does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * Oracle recommends including tracking information for the event or associated work, such as a ticket number.
         * 
         * Example: `Planned outage due to change IT-1234.`
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description Human-readable reason for this alarm suppression. It does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * Oracle recommends including tracking information for the event or associated work, such as a ticket number.
         * 
         * Example: `Planned outage due to change IT-1234.`
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param dimensions A filter to suppress only alarm state entries that include the set of specified dimension key-value pairs. If you specify {&#34;availabilityDomain&#34;: &#34;phx-ad-1&#34;} and the alarm state entry corresponds to the set {&#34;availabilityDomain&#34;: &#34;phx-ad-1&#34; and &#34;resourceId&#34;: &#34;instance.region1.phx.exampleuniqueID&#34;}, then this alarm will be included for suppression.
         * 
         * This is required only when the value of level is `DIMENSION`. If required, the value cannot be an empty object. Only a single value is allowed per key. No grouping of multiple values is allowed under the same key. Maximum characters (after serialization): 4000. This maximum satisfies typical use cases. The response for an exceeded maximum is `HTTP 400` with an &#34;dimensions values are too long&#34; message.
         * 
         * @return builder
         * 
         */
        public Builder dimensions(@Nullable Output<Map<String,String>> dimensions) {
            $.dimensions = dimensions;
            return this;
        }

        /**
         * @param dimensions A filter to suppress only alarm state entries that include the set of specified dimension key-value pairs. If you specify {&#34;availabilityDomain&#34;: &#34;phx-ad-1&#34;} and the alarm state entry corresponds to the set {&#34;availabilityDomain&#34;: &#34;phx-ad-1&#34; and &#34;resourceId&#34;: &#34;instance.region1.phx.exampleuniqueID&#34;}, then this alarm will be included for suppression.
         * 
         * This is required only when the value of level is `DIMENSION`. If required, the value cannot be an empty object. Only a single value is allowed per key. No grouping of multiple values is allowed under the same key. Maximum characters (after serialization): 4000. This maximum satisfies typical use cases. The response for an exceeded maximum is `HTTP 400` with an &#34;dimensions values are too long&#34; message.
         * 
         * @return builder
         * 
         */
        public Builder dimensions(Map<String,String> dimensions) {
            return dimensions(Output.of(dimensions));
        }

        /**
         * @param displayName A user-friendly name for the alarm suppression. It does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A user-friendly name for the alarm suppression. It does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param level The level of this alarm suppression. `ALARM` indicates a suppression of the entire alarm, regardless of dimension. `DIMENSION` indicates a suppression configured for specified dimensions.
         * 
         * Defaut: `DIMENSION`
         * 
         * @return builder
         * 
         */
        public Builder level(@Nullable Output<String> level) {
            $.level = level;
            return this;
        }

        /**
         * @param level The level of this alarm suppression. `ALARM` indicates a suppression of the entire alarm, regardless of dimension. `DIMENSION` indicates a suppression configured for specified dimensions.
         * 
         * Defaut: `DIMENSION`
         * 
         * @return builder
         * 
         */
        public Builder level(String level) {
            return level(Output.of(level));
        }

        /**
         * @param suppressionConditions Array of all preconditions for alarm suppression. Example: `[{ conditionType: &#34;RECURRENCE&#34;, suppressionRecurrence: &#34;FRQ=DAILY;BYHOUR=10&#34;, suppressionDuration: &#34;PT1H&#34; }]`
         * 
         * @return builder
         * 
         */
        public Builder suppressionConditions(@Nullable Output<List<AlarmSuppressionSuppressionConditionArgs>> suppressionConditions) {
            $.suppressionConditions = suppressionConditions;
            return this;
        }

        /**
         * @param suppressionConditions Array of all preconditions for alarm suppression. Example: `[{ conditionType: &#34;RECURRENCE&#34;, suppressionRecurrence: &#34;FRQ=DAILY;BYHOUR=10&#34;, suppressionDuration: &#34;PT1H&#34; }]`
         * 
         * @return builder
         * 
         */
        public Builder suppressionConditions(List<AlarmSuppressionSuppressionConditionArgs> suppressionConditions) {
            return suppressionConditions(Output.of(suppressionConditions));
        }

        /**
         * @param suppressionConditions Array of all preconditions for alarm suppression. Example: `[{ conditionType: &#34;RECURRENCE&#34;, suppressionRecurrence: &#34;FRQ=DAILY;BYHOUR=10&#34;, suppressionDuration: &#34;PT1H&#34; }]`
         * 
         * @return builder
         * 
         */
        public Builder suppressionConditions(AlarmSuppressionSuppressionConditionArgs... suppressionConditions) {
            return suppressionConditions(List.of(suppressionConditions));
        }

        /**
         * @param timeSuppressFrom The start date and time for the suppression to take place, inclusive. Format defined by RFC3339.  Example: `2023-02-01T01:02:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeSuppressFrom(Output<String> timeSuppressFrom) {
            $.timeSuppressFrom = timeSuppressFrom;
            return this;
        }

        /**
         * @param timeSuppressFrom The start date and time for the suppression to take place, inclusive. Format defined by RFC3339.  Example: `2023-02-01T01:02:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeSuppressFrom(String timeSuppressFrom) {
            return timeSuppressFrom(Output.of(timeSuppressFrom));
        }

        /**
         * @param timeSuppressUntil The end date and time for the suppression to take place, inclusive. Format defined by RFC3339.  Example: `2023-02-01T02:02:29.600Z`
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder timeSuppressUntil(Output<String> timeSuppressUntil) {
            $.timeSuppressUntil = timeSuppressUntil;
            return this;
        }

        /**
         * @param timeSuppressUntil The end date and time for the suppression to take place, inclusive. Format defined by RFC3339.  Example: `2023-02-01T02:02:29.600Z`
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder timeSuppressUntil(String timeSuppressUntil) {
            return timeSuppressUntil(Output.of(timeSuppressUntil));
        }

        public AlarmSuppressionArgs build() {
            if ($.alarmSuppressionTarget == null) {
                throw new MissingRequiredPropertyException("AlarmSuppressionArgs", "alarmSuppressionTarget");
            }
            if ($.displayName == null) {
                throw new MissingRequiredPropertyException("AlarmSuppressionArgs", "displayName");
            }
            if ($.timeSuppressFrom == null) {
                throw new MissingRequiredPropertyException("AlarmSuppressionArgs", "timeSuppressFrom");
            }
            if ($.timeSuppressUntil == null) {
                throw new MissingRequiredPropertyException("AlarmSuppressionArgs", "timeSuppressUntil");
            }
            return $;
        }
    }

}
