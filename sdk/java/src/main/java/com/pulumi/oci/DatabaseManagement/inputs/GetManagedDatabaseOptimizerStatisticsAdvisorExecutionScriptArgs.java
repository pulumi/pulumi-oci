// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptArgs Empty = new GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptArgs();

    /**
     * The name of the Optimizer Statistics Advisor execution.
     * 
     */
    @Import(name="executionName", required=true)
    private Output<String> executionName;

    /**
     * @return The name of the Optimizer Statistics Advisor execution.
     * 
     */
    public Output<String> executionName() {
        return this.executionName;
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     * 
     */
    @Import(name="managedDatabaseId", required=true)
    private Output<String> managedDatabaseId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     * 
     */
    public Output<String> managedDatabaseId() {
        return this.managedDatabaseId;
    }

    /**
     * The name of the optimizer statistics collection execution task.
     * 
     */
    @Import(name="taskName", required=true)
    private Output<String> taskName;

    /**
     * @return The name of the optimizer statistics collection execution task.
     * 
     */
    public Output<String> taskName() {
        return this.taskName;
    }

    private GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptArgs() {}

    private GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptArgs(GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptArgs $) {
        this.executionName = $.executionName;
        this.managedDatabaseId = $.managedDatabaseId;
        this.taskName = $.taskName;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptArgs $;

        public Builder() {
            $ = new GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptArgs();
        }

        public Builder(GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptArgs defaults) {
            $ = new GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param executionName The name of the Optimizer Statistics Advisor execution.
         * 
         * @return builder
         * 
         */
        public Builder executionName(Output<String> executionName) {
            $.executionName = executionName;
            return this;
        }

        /**
         * @param executionName The name of the Optimizer Statistics Advisor execution.
         * 
         * @return builder
         * 
         */
        public Builder executionName(String executionName) {
            return executionName(Output.of(executionName));
        }

        /**
         * @param managedDatabaseId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
         * 
         * @return builder
         * 
         */
        public Builder managedDatabaseId(Output<String> managedDatabaseId) {
            $.managedDatabaseId = managedDatabaseId;
            return this;
        }

        /**
         * @param managedDatabaseId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
         * 
         * @return builder
         * 
         */
        public Builder managedDatabaseId(String managedDatabaseId) {
            return managedDatabaseId(Output.of(managedDatabaseId));
        }

        /**
         * @param taskName The name of the optimizer statistics collection execution task.
         * 
         * @return builder
         * 
         */
        public Builder taskName(Output<String> taskName) {
            $.taskName = taskName;
            return this;
        }

        /**
         * @param taskName The name of the optimizer statistics collection execution task.
         * 
         * @return builder
         * 
         */
        public Builder taskName(String taskName) {
            return taskName(Output.of(taskName));
        }

        public GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptArgs build() {
            if ($.executionName == null) {
                throw new MissingRequiredPropertyException("GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptArgs", "executionName");
            }
            if ($.managedDatabaseId == null) {
                throw new MissingRequiredPropertyException("GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptArgs", "managedDatabaseId");
            }
            if ($.taskName == null) {
                throw new MissingRequiredPropertyException("GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptArgs", "taskName");
            }
            return $;
        }
    }

}
