// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetDatabaseSecurityConfigPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDatabaseSecurityConfigPlainArgs Empty = new GetDatabaseSecurityConfigPlainArgs();

    /**
     * The OCID of the database security configuration resource.
     * 
     */
    @Import(name="databaseSecurityConfigId", required=true)
    private String databaseSecurityConfigId;

    /**
     * @return The OCID of the database security configuration resource.
     * 
     */
    public String databaseSecurityConfigId() {
        return this.databaseSecurityConfigId;
    }

    private GetDatabaseSecurityConfigPlainArgs() {}

    private GetDatabaseSecurityConfigPlainArgs(GetDatabaseSecurityConfigPlainArgs $) {
        this.databaseSecurityConfigId = $.databaseSecurityConfigId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDatabaseSecurityConfigPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDatabaseSecurityConfigPlainArgs $;

        public Builder() {
            $ = new GetDatabaseSecurityConfigPlainArgs();
        }

        public Builder(GetDatabaseSecurityConfigPlainArgs defaults) {
            $ = new GetDatabaseSecurityConfigPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param databaseSecurityConfigId The OCID of the database security configuration resource.
         * 
         * @return builder
         * 
         */
        public Builder databaseSecurityConfigId(String databaseSecurityConfigId) {
            $.databaseSecurityConfigId = databaseSecurityConfigId;
            return this;
        }

        public GetDatabaseSecurityConfigPlainArgs build() {
            $.databaseSecurityConfigId = Objects.requireNonNull($.databaseSecurityConfigId, "expected parameter 'databaseSecurityConfigId' to be non-null");
            return $;
        }
    }

}