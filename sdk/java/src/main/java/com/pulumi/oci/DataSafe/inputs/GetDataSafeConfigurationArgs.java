// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetDataSafeConfigurationArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDataSafeConfigurationArgs Empty = new GetDataSafeConfigurationArgs();

    /**
     * A filter to return only resources that match the specified compartment OCID.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return A filter to return only resources that match the specified compartment OCID.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    private GetDataSafeConfigurationArgs() {}

    private GetDataSafeConfigurationArgs(GetDataSafeConfigurationArgs $) {
        this.compartmentId = $.compartmentId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDataSafeConfigurationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDataSafeConfigurationArgs $;

        public Builder() {
            $ = new GetDataSafeConfigurationArgs();
        }

        public Builder(GetDataSafeConfigurationArgs defaults) {
            $ = new GetDataSafeConfigurationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId A filter to return only resources that match the specified compartment OCID.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId A filter to return only resources that match the specified compartment OCID.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public GetDataSafeConfigurationArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}