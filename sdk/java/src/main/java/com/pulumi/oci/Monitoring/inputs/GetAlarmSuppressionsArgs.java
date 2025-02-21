// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Monitoring.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Monitoring.inputs.GetAlarmSuppressionsFilterArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetAlarmSuppressionsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAlarmSuppressionsArgs Empty = new GetAlarmSuppressionsArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the alarm that is the target of the alarm suppression.
     * 
     */
    @Import(name="alarmId")
    private @Nullable Output<String> alarmId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the alarm that is the target of the alarm suppression.
     * 
     */
    public Optional<Output<String>> alarmId() {
        return Optional.ofNullable(this.alarmId);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment for searching.  Use the tenancy OCID to search in the root compartment.
     * 
     * If targetType is not specified, searches all suppressions defined under the compartment.  If targetType is `COMPARTMENT`, searches suppressions in the specified compartment only.
     * 
     * Example: `ocid1.compartment.oc1..exampleuniqueID`
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment for searching.  Use the tenancy OCID to search in the root compartment.
     * 
     * If targetType is not specified, searches all suppressions defined under the compartment.  If targetType is `COMPARTMENT`, searches suppressions in the specified compartment only.
     * 
     * Example: `ocid1.compartment.oc1..exampleuniqueID`
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * When true, returns resources from all compartments and subcompartments. The parameter can only be set to true when compartmentId is the tenancy OCID (the tenancy is the root compartment). A true value requires the user to have tenancy-level permissions. If this requirement is not met, then the call is rejected. When false, returns resources from only the compartment specified in compartmentId. Default is false.
     * 
     */
    @Import(name="compartmentIdInSubtree")
    private @Nullable Output<Boolean> compartmentIdInSubtree;

    /**
     * @return When true, returns resources from all compartments and subcompartments. The parameter can only be set to true when compartmentId is the tenancy OCID (the tenancy is the root compartment). A true value requires the user to have tenancy-level permissions. If this requirement is not met, then the call is rejected. When false, returns resources from only the compartment specified in compartmentId. Default is false.
     * 
     */
    public Optional<Output<Boolean>> compartmentIdInSubtree() {
        return Optional.ofNullable(this.compartmentIdInSubtree);
    }

    /**
     * A filter to return only resources that match the given display name exactly. Use this filter to list an alarm suppression by name. Alternatively, when you know the alarm suppression OCID, use the GetAlarmSuppression operation.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A filter to return only resources that match the given display name exactly. Use this filter to list an alarm suppression by name. Alternatively, when you know the alarm suppression OCID, use the GetAlarmSuppression operation.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetAlarmSuppressionsFilterArgs>> filters;

    public Optional<Output<List<GetAlarmSuppressionsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Setting this parameter to true requires the query to specify the alarm (`alarmId`).
     * 
     * When true, lists all alarm suppressions that affect the specified alarm, including suppressions that target the corresponding compartment or tenancy. When false, lists only the alarm suppressions that target the specified alarm.
     * 
     * Default is false.
     * 
     */
    @Import(name="isAllSuppressions")
    private @Nullable Output<Boolean> isAllSuppressions;

    /**
     * @return Setting this parameter to true requires the query to specify the alarm (`alarmId`).
     * 
     * When true, lists all alarm suppressions that affect the specified alarm, including suppressions that target the corresponding compartment or tenancy. When false, lists only the alarm suppressions that target the specified alarm.
     * 
     * Default is false.
     * 
     */
    public Optional<Output<Boolean>> isAllSuppressions() {
        return Optional.ofNullable(this.isAllSuppressions);
    }

    /**
     * The level of this alarm suppression. `ALARM` indicates a suppression of the entire alarm, regardless of dimension. `DIMENSION` indicates a suppression configured for specified dimensions.
     * 
     */
    @Import(name="level")
    private @Nullable Output<String> level;

    /**
     * @return The level of this alarm suppression. `ALARM` indicates a suppression of the entire alarm, regardless of dimension. `DIMENSION` indicates a suppression configured for specified dimensions.
     * 
     */
    public Optional<Output<String>> level() {
        return Optional.ofNullable(this.level);
    }

    /**
     * A filter to return only resources that match the given lifecycle state exactly. When not specified, only resources in the ACTIVE lifecycle state are listed.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return A filter to return only resources that match the given lifecycle state exactly. When not specified, only resources in the ACTIVE lifecycle state are listed.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The target type to use when listing alarm suppressions.     `ALARM` lists all suppression records for the specified alarm. `COMPARTMENT` lists all suppression records for the specified compartment or tenancy.
     * 
     */
    @Import(name="targetType")
    private @Nullable Output<String> targetType;

    /**
     * @return The target type to use when listing alarm suppressions.     `ALARM` lists all suppression records for the specified alarm. `COMPARTMENT` lists all suppression records for the specified compartment or tenancy.
     * 
     */
    public Optional<Output<String>> targetType() {
        return Optional.ofNullable(this.targetType);
    }

    private GetAlarmSuppressionsArgs() {}

    private GetAlarmSuppressionsArgs(GetAlarmSuppressionsArgs $) {
        this.alarmId = $.alarmId;
        this.compartmentId = $.compartmentId;
        this.compartmentIdInSubtree = $.compartmentIdInSubtree;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.isAllSuppressions = $.isAllSuppressions;
        this.level = $.level;
        this.state = $.state;
        this.targetType = $.targetType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAlarmSuppressionsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAlarmSuppressionsArgs $;

        public Builder() {
            $ = new GetAlarmSuppressionsArgs();
        }

        public Builder(GetAlarmSuppressionsArgs defaults) {
            $ = new GetAlarmSuppressionsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param alarmId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the alarm that is the target of the alarm suppression.
         * 
         * @return builder
         * 
         */
        public Builder alarmId(@Nullable Output<String> alarmId) {
            $.alarmId = alarmId;
            return this;
        }

        /**
         * @param alarmId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the alarm that is the target of the alarm suppression.
         * 
         * @return builder
         * 
         */
        public Builder alarmId(String alarmId) {
            return alarmId(Output.of(alarmId));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment for searching.  Use the tenancy OCID to search in the root compartment.
         * 
         * If targetType is not specified, searches all suppressions defined under the compartment.  If targetType is `COMPARTMENT`, searches suppressions in the specified compartment only.
         * 
         * Example: `ocid1.compartment.oc1..exampleuniqueID`
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment for searching.  Use the tenancy OCID to search in the root compartment.
         * 
         * If targetType is not specified, searches all suppressions defined under the compartment.  If targetType is `COMPARTMENT`, searches suppressions in the specified compartment only.
         * 
         * Example: `ocid1.compartment.oc1..exampleuniqueID`
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param compartmentIdInSubtree When true, returns resources from all compartments and subcompartments. The parameter can only be set to true when compartmentId is the tenancy OCID (the tenancy is the root compartment). A true value requires the user to have tenancy-level permissions. If this requirement is not met, then the call is rejected. When false, returns resources from only the compartment specified in compartmentId. Default is false.
         * 
         * @return builder
         * 
         */
        public Builder compartmentIdInSubtree(@Nullable Output<Boolean> compartmentIdInSubtree) {
            $.compartmentIdInSubtree = compartmentIdInSubtree;
            return this;
        }

        /**
         * @param compartmentIdInSubtree When true, returns resources from all compartments and subcompartments. The parameter can only be set to true when compartmentId is the tenancy OCID (the tenancy is the root compartment). A true value requires the user to have tenancy-level permissions. If this requirement is not met, then the call is rejected. When false, returns resources from only the compartment specified in compartmentId. Default is false.
         * 
         * @return builder
         * 
         */
        public Builder compartmentIdInSubtree(Boolean compartmentIdInSubtree) {
            return compartmentIdInSubtree(Output.of(compartmentIdInSubtree));
        }

        /**
         * @param displayName A filter to return only resources that match the given display name exactly. Use this filter to list an alarm suppression by name. Alternatively, when you know the alarm suppression OCID, use the GetAlarmSuppression operation.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A filter to return only resources that match the given display name exactly. Use this filter to list an alarm suppression by name. Alternatively, when you know the alarm suppression OCID, use the GetAlarmSuppression operation.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder filters(@Nullable Output<List<GetAlarmSuppressionsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetAlarmSuppressionsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetAlarmSuppressionsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param isAllSuppressions Setting this parameter to true requires the query to specify the alarm (`alarmId`).
         * 
         * When true, lists all alarm suppressions that affect the specified alarm, including suppressions that target the corresponding compartment or tenancy. When false, lists only the alarm suppressions that target the specified alarm.
         * 
         * Default is false.
         * 
         * @return builder
         * 
         */
        public Builder isAllSuppressions(@Nullable Output<Boolean> isAllSuppressions) {
            $.isAllSuppressions = isAllSuppressions;
            return this;
        }

        /**
         * @param isAllSuppressions Setting this parameter to true requires the query to specify the alarm (`alarmId`).
         * 
         * When true, lists all alarm suppressions that affect the specified alarm, including suppressions that target the corresponding compartment or tenancy. When false, lists only the alarm suppressions that target the specified alarm.
         * 
         * Default is false.
         * 
         * @return builder
         * 
         */
        public Builder isAllSuppressions(Boolean isAllSuppressions) {
            return isAllSuppressions(Output.of(isAllSuppressions));
        }

        /**
         * @param level The level of this alarm suppression. `ALARM` indicates a suppression of the entire alarm, regardless of dimension. `DIMENSION` indicates a suppression configured for specified dimensions.
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
         * @return builder
         * 
         */
        public Builder level(String level) {
            return level(Output.of(level));
        }

        /**
         * @param state A filter to return only resources that match the given lifecycle state exactly. When not specified, only resources in the ACTIVE lifecycle state are listed.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state A filter to return only resources that match the given lifecycle state exactly. When not specified, only resources in the ACTIVE lifecycle state are listed.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param targetType The target type to use when listing alarm suppressions.     `ALARM` lists all suppression records for the specified alarm. `COMPARTMENT` lists all suppression records for the specified compartment or tenancy.
         * 
         * @return builder
         * 
         */
        public Builder targetType(@Nullable Output<String> targetType) {
            $.targetType = targetType;
            return this;
        }

        /**
         * @param targetType The target type to use when listing alarm suppressions.     `ALARM` lists all suppression records for the specified alarm. `COMPARTMENT` lists all suppression records for the specified compartment or tenancy.
         * 
         * @return builder
         * 
         */
        public Builder targetType(String targetType) {
            return targetType(Output.of(targetType));
        }

        public GetAlarmSuppressionsArgs build() {
            return $;
        }
    }

}
