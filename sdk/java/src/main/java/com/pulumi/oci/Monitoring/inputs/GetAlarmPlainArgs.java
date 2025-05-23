// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Monitoring.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetAlarmPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAlarmPlainArgs Empty = new GetAlarmPlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of an alarm.
     * 
     */
    @Import(name="alarmId", required=true)
    private String alarmId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of an alarm.
     * 
     */
    public String alarmId() {
        return this.alarmId;
    }

    private GetAlarmPlainArgs() {}

    private GetAlarmPlainArgs(GetAlarmPlainArgs $) {
        this.alarmId = $.alarmId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAlarmPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAlarmPlainArgs $;

        public Builder() {
            $ = new GetAlarmPlainArgs();
        }

        public Builder(GetAlarmPlainArgs defaults) {
            $ = new GetAlarmPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param alarmId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of an alarm.
         * 
         * @return builder
         * 
         */
        public Builder alarmId(String alarmId) {
            $.alarmId = alarmId;
            return this;
        }

        public GetAlarmPlainArgs build() {
            if ($.alarmId == null) {
                throw new MissingRequiredPropertyException("GetAlarmPlainArgs", "alarmId");
            }
            return $;
        }
    }

}
