// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetDbHomeArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDbHomeArgs Empty = new GetDbHomeArgs();

    /**
     * The Database Home [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="dbHomeId", required=true)
    private Output<String> dbHomeId;

    /**
     * @return The Database Home [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Output<String> dbHomeId() {
        return this.dbHomeId;
    }

    private GetDbHomeArgs() {}

    private GetDbHomeArgs(GetDbHomeArgs $) {
        this.dbHomeId = $.dbHomeId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDbHomeArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDbHomeArgs $;

        public Builder() {
            $ = new GetDbHomeArgs();
        }

        public Builder(GetDbHomeArgs defaults) {
            $ = new GetDbHomeArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param dbHomeId The Database Home [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder dbHomeId(Output<String> dbHomeId) {
            $.dbHomeId = dbHomeId;
            return this;
        }

        /**
         * @param dbHomeId The Database Home [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder dbHomeId(String dbHomeId) {
            return dbHomeId(Output.of(dbHomeId));
        }

        public GetDbHomeArgs build() {
            if ($.dbHomeId == null) {
                throw new MissingRequiredPropertyException("GetDbHomeArgs", "dbHomeId");
            }
            return $;
        }
    }

}
