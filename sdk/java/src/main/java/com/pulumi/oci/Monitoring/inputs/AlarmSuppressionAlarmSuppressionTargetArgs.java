// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Monitoring.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class AlarmSuppressionAlarmSuppressionTargetArgs extends com.pulumi.resources.ResourceArgs {

    public static final AlarmSuppressionAlarmSuppressionTargetArgs Empty = new AlarmSuppressionAlarmSuppressionTargetArgs();

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
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment or tenancy that is the  target of the alarm suppression. Example: `ocid1.compartment.oc1..exampleuniqueID`
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment or tenancy that is the  target of the alarm suppression. Example: `ocid1.compartment.oc1..exampleuniqueID`
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * When true, the alarm suppression targets all alarms under all compartments and subcompartments of  the tenancy specified. The parameter can only be set to true when compartmentId is the tenancy OCID  (the tenancy is the root compartment). When false, the alarm suppression targets only the alarms under the specified compartment.
     * 
     */
    @Import(name="compartmentIdInSubtree")
    private @Nullable Output<Boolean> compartmentIdInSubtree;

    /**
     * @return When true, the alarm suppression targets all alarms under all compartments and subcompartments of  the tenancy specified. The parameter can only be set to true when compartmentId is the tenancy OCID  (the tenancy is the root compartment). When false, the alarm suppression targets only the alarms under the specified compartment.
     * 
     */
    public Optional<Output<Boolean>> compartmentIdInSubtree() {
        return Optional.ofNullable(this.compartmentIdInSubtree);
    }

    /**
     * The type of the alarm suppression target.
     * 
     */
    @Import(name="targetType", required=true)
    private Output<String> targetType;

    /**
     * @return The type of the alarm suppression target.
     * 
     */
    public Output<String> targetType() {
        return this.targetType;
    }

    private AlarmSuppressionAlarmSuppressionTargetArgs() {}

    private AlarmSuppressionAlarmSuppressionTargetArgs(AlarmSuppressionAlarmSuppressionTargetArgs $) {
        this.alarmId = $.alarmId;
        this.compartmentId = $.compartmentId;
        this.compartmentIdInSubtree = $.compartmentIdInSubtree;
        this.targetType = $.targetType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(AlarmSuppressionAlarmSuppressionTargetArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private AlarmSuppressionAlarmSuppressionTargetArgs $;

        public Builder() {
            $ = new AlarmSuppressionAlarmSuppressionTargetArgs();
        }

        public Builder(AlarmSuppressionAlarmSuppressionTargetArgs defaults) {
            $ = new AlarmSuppressionAlarmSuppressionTargetArgs(Objects.requireNonNull(defaults));
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
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment or tenancy that is the  target of the alarm suppression. Example: `ocid1.compartment.oc1..exampleuniqueID`
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment or tenancy that is the  target of the alarm suppression. Example: `ocid1.compartment.oc1..exampleuniqueID`
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param compartmentIdInSubtree When true, the alarm suppression targets all alarms under all compartments and subcompartments of  the tenancy specified. The parameter can only be set to true when compartmentId is the tenancy OCID  (the tenancy is the root compartment). When false, the alarm suppression targets only the alarms under the specified compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentIdInSubtree(@Nullable Output<Boolean> compartmentIdInSubtree) {
            $.compartmentIdInSubtree = compartmentIdInSubtree;
            return this;
        }

        /**
         * @param compartmentIdInSubtree When true, the alarm suppression targets all alarms under all compartments and subcompartments of  the tenancy specified. The parameter can only be set to true when compartmentId is the tenancy OCID  (the tenancy is the root compartment). When false, the alarm suppression targets only the alarms under the specified compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentIdInSubtree(Boolean compartmentIdInSubtree) {
            return compartmentIdInSubtree(Output.of(compartmentIdInSubtree));
        }

        /**
         * @param targetType The type of the alarm suppression target.
         * 
         * @return builder
         * 
         */
        public Builder targetType(Output<String> targetType) {
            $.targetType = targetType;
            return this;
        }

        /**
         * @param targetType The type of the alarm suppression target.
         * 
         * @return builder
         * 
         */
        public Builder targetType(String targetType) {
            return targetType(Output.of(targetType));
        }

        public AlarmSuppressionAlarmSuppressionTargetArgs build() {
            if ($.targetType == null) {
                throw new MissingRequiredPropertyException("AlarmSuppressionAlarmSuppressionTargetArgs", "targetType");
            }
            return $;
        }
    }

}
