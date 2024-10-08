// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetExternalDbHomeArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetExternalDbHomeArgs Empty = new GetExternalDbHomeArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database home.
     * 
     */
    @Import(name="externalDbHomeId", required=true)
    private Output<String> externalDbHomeId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database home.
     * 
     */
    public Output<String> externalDbHomeId() {
        return this.externalDbHomeId;
    }

    private GetExternalDbHomeArgs() {}

    private GetExternalDbHomeArgs(GetExternalDbHomeArgs $) {
        this.externalDbHomeId = $.externalDbHomeId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetExternalDbHomeArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetExternalDbHomeArgs $;

        public Builder() {
            $ = new GetExternalDbHomeArgs();
        }

        public Builder(GetExternalDbHomeArgs defaults) {
            $ = new GetExternalDbHomeArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param externalDbHomeId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database home.
         * 
         * @return builder
         * 
         */
        public Builder externalDbHomeId(Output<String> externalDbHomeId) {
            $.externalDbHomeId = externalDbHomeId;
            return this;
        }

        /**
         * @param externalDbHomeId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database home.
         * 
         * @return builder
         * 
         */
        public Builder externalDbHomeId(String externalDbHomeId) {
            return externalDbHomeId(Output.of(externalDbHomeId));
        }

        public GetExternalDbHomeArgs build() {
            if ($.externalDbHomeId == null) {
                throw new MissingRequiredPropertyException("GetExternalDbHomeArgs", "externalDbHomeId");
            }
            return $;
        }
    }

}
