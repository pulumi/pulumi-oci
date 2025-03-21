// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptPlainArgs Empty = new GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptPlainArgs();

    /**
     * The name of the Optimizer Statistics Advisor execution.
     * 
     */
    @Import(name="executionName", required=true)
    private String executionName;

    /**
     * @return The name of the Optimizer Statistics Advisor execution.
     * 
     */
    public String executionName() {
        return this.executionName;
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     * 
     */
    @Import(name="managedDatabaseId", required=true)
    private String managedDatabaseId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     * 
     */
    public String managedDatabaseId() {
        return this.managedDatabaseId;
    }

    /**
     * The name of the optimizer statistics collection execution task.
     * 
     */
    @Import(name="taskName", required=true)
    private String taskName;

    /**
     * @return The name of the optimizer statistics collection execution task.
     * 
     */
    public String taskName() {
        return this.taskName;
    }

    private GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptPlainArgs() {}

    private GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptPlainArgs(GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptPlainArgs $) {
        this.executionName = $.executionName;
        this.managedDatabaseId = $.managedDatabaseId;
        this.taskName = $.taskName;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptPlainArgs $;

        public Builder() {
            $ = new GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptPlainArgs();
        }

        public Builder(GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptPlainArgs defaults) {
            $ = new GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param executionName The name of the Optimizer Statistics Advisor execution.
         * 
         * @return builder
         * 
         */
        public Builder executionName(String executionName) {
            $.executionName = executionName;
            return this;
        }

        /**
         * @param managedDatabaseId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
         * 
         * @return builder
         * 
         */
        public Builder managedDatabaseId(String managedDatabaseId) {
            $.managedDatabaseId = managedDatabaseId;
            return this;
        }

        /**
         * @param taskName The name of the optimizer statistics collection execution task.
         * 
         * @return builder
         * 
         */
        public Builder taskName(String taskName) {
            $.taskName = taskName;
            return this;
        }

        public GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptPlainArgs build() {
            if ($.executionName == null) {
                throw new MissingRequiredPropertyException("GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptPlainArgs", "executionName");
            }
            if ($.managedDatabaseId == null) {
                throw new MissingRequiredPropertyException("GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptPlainArgs", "managedDatabaseId");
            }
            if ($.taskName == null) {
                throw new MissingRequiredPropertyException("GetManagedDatabaseOptimizerStatisticsAdvisorExecutionScriptPlainArgs", "taskName");
            }
            return $;
        }
    }

}
