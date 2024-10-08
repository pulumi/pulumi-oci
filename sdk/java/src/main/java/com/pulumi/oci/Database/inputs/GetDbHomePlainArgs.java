// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetDbHomePlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDbHomePlainArgs Empty = new GetDbHomePlainArgs();

    /**
     * The Database Home [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="dbHomeId", required=true)
    private String dbHomeId;

    /**
     * @return The Database Home [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public String dbHomeId() {
        return this.dbHomeId;
    }

    private GetDbHomePlainArgs() {}

    private GetDbHomePlainArgs(GetDbHomePlainArgs $) {
        this.dbHomeId = $.dbHomeId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDbHomePlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDbHomePlainArgs $;

        public Builder() {
            $ = new GetDbHomePlainArgs();
        }

        public Builder(GetDbHomePlainArgs defaults) {
            $ = new GetDbHomePlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param dbHomeId The Database Home [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder dbHomeId(String dbHomeId) {
            $.dbHomeId = dbHomeId;
            return this;
        }

        public GetDbHomePlainArgs build() {
            if ($.dbHomeId == null) {
                throw new MissingRequiredPropertyException("GetDbHomePlainArgs", "dbHomeId");
            }
            return $;
        }
    }

}
