// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetTaskRecordArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetTaskRecordArgs Empty = new GetTaskRecordArgs();

    /**
     * unique TaskDetail identifier
     * 
     */
    @Import(name="taskRecordId", required=true)
    private Output<String> taskRecordId;

    /**
     * @return unique TaskDetail identifier
     * 
     */
    public Output<String> taskRecordId() {
        return this.taskRecordId;
    }

    private GetTaskRecordArgs() {}

    private GetTaskRecordArgs(GetTaskRecordArgs $) {
        this.taskRecordId = $.taskRecordId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetTaskRecordArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetTaskRecordArgs $;

        public Builder() {
            $ = new GetTaskRecordArgs();
        }

        public Builder(GetTaskRecordArgs defaults) {
            $ = new GetTaskRecordArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param taskRecordId unique TaskDetail identifier
         * 
         * @return builder
         * 
         */
        public Builder taskRecordId(Output<String> taskRecordId) {
            $.taskRecordId = taskRecordId;
            return this;
        }

        /**
         * @param taskRecordId unique TaskDetail identifier
         * 
         * @return builder
         * 
         */
        public Builder taskRecordId(String taskRecordId) {
            return taskRecordId(Output.of(taskRecordId));
        }

        public GetTaskRecordArgs build() {
            if ($.taskRecordId == null) {
                throw new MissingRequiredPropertyException("GetTaskRecordArgs", "taskRecordId");
            }
            return $;
        }
    }

}
