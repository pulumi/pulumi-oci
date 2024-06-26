// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.EmWarehouse.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetEmWarehouseArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetEmWarehouseArgs Empty = new GetEmWarehouseArgs();

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

    private GetEmWarehouseArgs() {}

    private GetEmWarehouseArgs(GetEmWarehouseArgs $) {
        this.emWarehouseId = $.emWarehouseId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetEmWarehouseArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetEmWarehouseArgs $;

        public Builder() {
            $ = new GetEmWarehouseArgs();
        }

        public Builder(GetEmWarehouseArgs defaults) {
            $ = new GetEmWarehouseArgs(Objects.requireNonNull(defaults));
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

        public GetEmWarehouseArgs build() {
            if ($.emWarehouseId == null) {
                throw new MissingRequiredPropertyException("GetEmWarehouseArgs", "emWarehouseId");
            }
            return $;
        }
    }

}
