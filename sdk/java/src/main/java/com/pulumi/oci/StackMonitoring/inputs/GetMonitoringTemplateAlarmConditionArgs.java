// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetMonitoringTemplateAlarmConditionArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetMonitoringTemplateAlarmConditionArgs Empty = new GetMonitoringTemplateAlarmConditionArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the alarm condition.
     * 
     */
    @Import(name="alarmConditionId", required=true)
    private Output<String> alarmConditionId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the alarm condition.
     * 
     */
    public Output<String> alarmConditionId() {
        return this.alarmConditionId;
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the monitoring template.
     * 
     */
    @Import(name="monitoringTemplateId", required=true)
    private Output<String> monitoringTemplateId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the monitoring template.
     * 
     */
    public Output<String> monitoringTemplateId() {
        return this.monitoringTemplateId;
    }

    private GetMonitoringTemplateAlarmConditionArgs() {}

    private GetMonitoringTemplateAlarmConditionArgs(GetMonitoringTemplateAlarmConditionArgs $) {
        this.alarmConditionId = $.alarmConditionId;
        this.monitoringTemplateId = $.monitoringTemplateId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetMonitoringTemplateAlarmConditionArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetMonitoringTemplateAlarmConditionArgs $;

        public Builder() {
            $ = new GetMonitoringTemplateAlarmConditionArgs();
        }

        public Builder(GetMonitoringTemplateAlarmConditionArgs defaults) {
            $ = new GetMonitoringTemplateAlarmConditionArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param alarmConditionId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the alarm condition.
         * 
         * @return builder
         * 
         */
        public Builder alarmConditionId(Output<String> alarmConditionId) {
            $.alarmConditionId = alarmConditionId;
            return this;
        }

        /**
         * @param alarmConditionId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the alarm condition.
         * 
         * @return builder
         * 
         */
        public Builder alarmConditionId(String alarmConditionId) {
            return alarmConditionId(Output.of(alarmConditionId));
        }

        /**
         * @param monitoringTemplateId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the monitoring template.
         * 
         * @return builder
         * 
         */
        public Builder monitoringTemplateId(Output<String> monitoringTemplateId) {
            $.monitoringTemplateId = monitoringTemplateId;
            return this;
        }

        /**
         * @param monitoringTemplateId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the monitoring template.
         * 
         * @return builder
         * 
         */
        public Builder monitoringTemplateId(String monitoringTemplateId) {
            return monitoringTemplateId(Output.of(monitoringTemplateId));
        }

        public GetMonitoringTemplateAlarmConditionArgs build() {
            if ($.alarmConditionId == null) {
                throw new MissingRequiredPropertyException("GetMonitoringTemplateAlarmConditionArgs", "alarmConditionId");
            }
            if ($.monitoringTemplateId == null) {
                throw new MissingRequiredPropertyException("GetMonitoringTemplateAlarmConditionArgs", "monitoringTemplateId");
            }
            return $;
        }
    }

}
