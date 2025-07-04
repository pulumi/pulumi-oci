// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CapacityManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetOccmDemandSignalItemArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetOccmDemandSignalItemArgs Empty = new GetOccmDemandSignalItemArgs();

    /**
     * The OCID of the demand signal item.
     * 
     */
    @Import(name="occmDemandSignalItemId", required=true)
    private Output<String> occmDemandSignalItemId;

    /**
     * @return The OCID of the demand signal item.
     * 
     */
    public Output<String> occmDemandSignalItemId() {
        return this.occmDemandSignalItemId;
    }

    private GetOccmDemandSignalItemArgs() {}

    private GetOccmDemandSignalItemArgs(GetOccmDemandSignalItemArgs $) {
        this.occmDemandSignalItemId = $.occmDemandSignalItemId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetOccmDemandSignalItemArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetOccmDemandSignalItemArgs $;

        public Builder() {
            $ = new GetOccmDemandSignalItemArgs();
        }

        public Builder(GetOccmDemandSignalItemArgs defaults) {
            $ = new GetOccmDemandSignalItemArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param occmDemandSignalItemId The OCID of the demand signal item.
         * 
         * @return builder
         * 
         */
        public Builder occmDemandSignalItemId(Output<String> occmDemandSignalItemId) {
            $.occmDemandSignalItemId = occmDemandSignalItemId;
            return this;
        }

        /**
         * @param occmDemandSignalItemId The OCID of the demand signal item.
         * 
         * @return builder
         * 
         */
        public Builder occmDemandSignalItemId(String occmDemandSignalItemId) {
            return occmDemandSignalItemId(Output.of(occmDemandSignalItemId));
        }

        public GetOccmDemandSignalItemArgs build() {
            if ($.occmDemandSignalItemId == null) {
                throw new MissingRequiredPropertyException("GetOccmDemandSignalItemArgs", "occmDemandSignalItemId");
            }
            return $;
        }
    }

}
