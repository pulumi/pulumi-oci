// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Ocvp.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetSddcArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSddcArgs Empty = new GetSddcArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the SDDC.
     * 
     */
    @Import(name="sddcId", required=true)
    private Output<String> sddcId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the SDDC.
     * 
     */
    public Output<String> sddcId() {
        return this.sddcId;
    }

    private GetSddcArgs() {}

    private GetSddcArgs(GetSddcArgs $) {
        this.sddcId = $.sddcId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSddcArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSddcArgs $;

        public Builder() {
            $ = new GetSddcArgs();
        }

        public Builder(GetSddcArgs defaults) {
            $ = new GetSddcArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param sddcId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the SDDC.
         * 
         * @return builder
         * 
         */
        public Builder sddcId(Output<String> sddcId) {
            $.sddcId = sddcId;
            return this;
        }

        /**
         * @param sddcId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the SDDC.
         * 
         * @return builder
         * 
         */
        public Builder sddcId(String sddcId) {
            return sddcId(Output.of(sddcId));
        }

        public GetSddcArgs build() {
            $.sddcId = Objects.requireNonNull($.sddcId, "expected parameter 'sddcId' to be non-null");
            return $;
        }
    }

}