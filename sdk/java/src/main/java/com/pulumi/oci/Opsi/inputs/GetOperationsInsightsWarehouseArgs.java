// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opsi.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetOperationsInsightsWarehouseArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetOperationsInsightsWarehouseArgs Empty = new GetOperationsInsightsWarehouseArgs();

    /**
     * Unique Operations Insights Warehouse identifier
     * 
     */
    @Import(name="operationsInsightsWarehouseId", required=true)
    private Output<String> operationsInsightsWarehouseId;

    /**
     * @return Unique Operations Insights Warehouse identifier
     * 
     */
    public Output<String> operationsInsightsWarehouseId() {
        return this.operationsInsightsWarehouseId;
    }

    private GetOperationsInsightsWarehouseArgs() {}

    private GetOperationsInsightsWarehouseArgs(GetOperationsInsightsWarehouseArgs $) {
        this.operationsInsightsWarehouseId = $.operationsInsightsWarehouseId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetOperationsInsightsWarehouseArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetOperationsInsightsWarehouseArgs $;

        public Builder() {
            $ = new GetOperationsInsightsWarehouseArgs();
        }

        public Builder(GetOperationsInsightsWarehouseArgs defaults) {
            $ = new GetOperationsInsightsWarehouseArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param operationsInsightsWarehouseId Unique Operations Insights Warehouse identifier
         * 
         * @return builder
         * 
         */
        public Builder operationsInsightsWarehouseId(Output<String> operationsInsightsWarehouseId) {
            $.operationsInsightsWarehouseId = operationsInsightsWarehouseId;
            return this;
        }

        /**
         * @param operationsInsightsWarehouseId Unique Operations Insights Warehouse identifier
         * 
         * @return builder
         * 
         */
        public Builder operationsInsightsWarehouseId(String operationsInsightsWarehouseId) {
            return operationsInsightsWarehouseId(Output.of(operationsInsightsWarehouseId));
        }

        public GetOperationsInsightsWarehouseArgs build() {
            $.operationsInsightsWarehouseId = Objects.requireNonNull($.operationsInsightsWarehouseId, "expected parameter 'operationsInsightsWarehouseId' to be non-null");
            return $;
        }
    }

}