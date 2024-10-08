// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Double;
import java.lang.String;
import java.util.Objects;


public final class GetManagedDatabaseOptimizerStatisticsCollectionOperationPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetManagedDatabaseOptimizerStatisticsCollectionOperationPlainArgs Empty = new GetManagedDatabaseOptimizerStatisticsCollectionOperationPlainArgs();

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
     * The ID of the Optimizer Statistics Collection operation.
     * 
     */
    @Import(name="optimizerStatisticsCollectionOperationId", required=true)
    private Double optimizerStatisticsCollectionOperationId;

    /**
     * @return The ID of the Optimizer Statistics Collection operation.
     * 
     */
    public Double optimizerStatisticsCollectionOperationId() {
        return this.optimizerStatisticsCollectionOperationId;
    }

    private GetManagedDatabaseOptimizerStatisticsCollectionOperationPlainArgs() {}

    private GetManagedDatabaseOptimizerStatisticsCollectionOperationPlainArgs(GetManagedDatabaseOptimizerStatisticsCollectionOperationPlainArgs $) {
        this.managedDatabaseId = $.managedDatabaseId;
        this.optimizerStatisticsCollectionOperationId = $.optimizerStatisticsCollectionOperationId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetManagedDatabaseOptimizerStatisticsCollectionOperationPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetManagedDatabaseOptimizerStatisticsCollectionOperationPlainArgs $;

        public Builder() {
            $ = new GetManagedDatabaseOptimizerStatisticsCollectionOperationPlainArgs();
        }

        public Builder(GetManagedDatabaseOptimizerStatisticsCollectionOperationPlainArgs defaults) {
            $ = new GetManagedDatabaseOptimizerStatisticsCollectionOperationPlainArgs(Objects.requireNonNull(defaults));
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
         * @param optimizerStatisticsCollectionOperationId The ID of the Optimizer Statistics Collection operation.
         * 
         * @return builder
         * 
         */
        public Builder optimizerStatisticsCollectionOperationId(Double optimizerStatisticsCollectionOperationId) {
            $.optimizerStatisticsCollectionOperationId = optimizerStatisticsCollectionOperationId;
            return this;
        }

        public GetManagedDatabaseOptimizerStatisticsCollectionOperationPlainArgs build() {
            if ($.managedDatabaseId == null) {
                throw new MissingRequiredPropertyException("GetManagedDatabaseOptimizerStatisticsCollectionOperationPlainArgs", "managedDatabaseId");
            }
            if ($.optimizerStatisticsCollectionOperationId == null) {
                throw new MissingRequiredPropertyException("GetManagedDatabaseOptimizerStatisticsCollectionOperationPlainArgs", "optimizerStatisticsCollectionOperationId");
            }
            return $;
        }
    }

}
