// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetExternalDbHomePlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetExternalDbHomePlainArgs Empty = new GetExternalDbHomePlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database home.
     * 
     */
    @Import(name="externalDbHomeId", required=true)
    private String externalDbHomeId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database home.
     * 
     */
    public String externalDbHomeId() {
        return this.externalDbHomeId;
    }

    private GetExternalDbHomePlainArgs() {}

    private GetExternalDbHomePlainArgs(GetExternalDbHomePlainArgs $) {
        this.externalDbHomeId = $.externalDbHomeId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetExternalDbHomePlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetExternalDbHomePlainArgs $;

        public Builder() {
            $ = new GetExternalDbHomePlainArgs();
        }

        public Builder(GetExternalDbHomePlainArgs defaults) {
            $ = new GetExternalDbHomePlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param externalDbHomeId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database home.
         * 
         * @return builder
         * 
         */
        public Builder externalDbHomeId(String externalDbHomeId) {
            $.externalDbHomeId = externalDbHomeId;
            return this;
        }

        public GetExternalDbHomePlainArgs build() {
            if ($.externalDbHomeId == null) {
                throw new MissingRequiredPropertyException("GetExternalDbHomePlainArgs", "externalDbHomeId");
            }
            return $;
        }
    }

}
