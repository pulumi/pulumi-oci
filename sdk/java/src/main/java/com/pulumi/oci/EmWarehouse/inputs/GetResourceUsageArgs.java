// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.EmWarehouse.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetResourceUsageArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetResourceUsageArgs Empty = new GetResourceUsageArgs();

    /**
     * unique EmWarehouse identifier
     * 
     */
    @Import(name="emWarehouseId", required=true)
    private Output<String> emWarehouseId;

    /**
     * @return unique EmWarehouse identifier
     * 
     */
    public Output<String> emWarehouseId() {
        return this.emWarehouseId;
    }

    private GetResourceUsageArgs() {}

    private GetResourceUsageArgs(GetResourceUsageArgs $) {
        this.emWarehouseId = $.emWarehouseId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetResourceUsageArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetResourceUsageArgs $;

        public Builder() {
            $ = new GetResourceUsageArgs();
        }

        public Builder(GetResourceUsageArgs defaults) {
            $ = new GetResourceUsageArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param emWarehouseId unique EmWarehouse identifier
         * 
         * @return builder
         * 
         */
        public Builder emWarehouseId(Output<String> emWarehouseId) {
            $.emWarehouseId = emWarehouseId;
            return this;
        }

        /**
         * @param emWarehouseId unique EmWarehouse identifier
         * 
         * @return builder
         * 
         */
        public Builder emWarehouseId(String emWarehouseId) {
            return emWarehouseId(Output.of(emWarehouseId));
        }

        public GetResourceUsageArgs build() {
            $.emWarehouseId = Objects.requireNonNull($.emWarehouseId, "expected parameter 'emWarehouseId' to be non-null");
            return $;
        }
    }

}