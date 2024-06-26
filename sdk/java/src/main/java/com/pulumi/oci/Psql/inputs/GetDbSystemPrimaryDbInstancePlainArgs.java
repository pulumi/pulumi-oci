// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Psql.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetDbSystemPrimaryDbInstancePlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDbSystemPrimaryDbInstancePlainArgs Empty = new GetDbSystemPrimaryDbInstancePlainArgs();

    /**
     * A unique identifier for the database system.
     * 
     */
    @Import(name="dbSystemId", required=true)
    private String dbSystemId;

    /**
     * @return A unique identifier for the database system.
     * 
     */
    public String dbSystemId() {
        return this.dbSystemId;
    }

    private GetDbSystemPrimaryDbInstancePlainArgs() {}

    private GetDbSystemPrimaryDbInstancePlainArgs(GetDbSystemPrimaryDbInstancePlainArgs $) {
        this.dbSystemId = $.dbSystemId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDbSystemPrimaryDbInstancePlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDbSystemPrimaryDbInstancePlainArgs $;

        public Builder() {
            $ = new GetDbSystemPrimaryDbInstancePlainArgs();
        }

        public Builder(GetDbSystemPrimaryDbInstancePlainArgs defaults) {
            $ = new GetDbSystemPrimaryDbInstancePlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param dbSystemId A unique identifier for the database system.
         * 
         * @return builder
         * 
         */
        public Builder dbSystemId(String dbSystemId) {
            $.dbSystemId = dbSystemId;
            return this;
        }

        public GetDbSystemPrimaryDbInstancePlainArgs build() {
            if ($.dbSystemId == null) {
                throw new MissingRequiredPropertyException("GetDbSystemPrimaryDbInstancePlainArgs", "dbSystemId");
            }
            return $;
        }
    }

}
