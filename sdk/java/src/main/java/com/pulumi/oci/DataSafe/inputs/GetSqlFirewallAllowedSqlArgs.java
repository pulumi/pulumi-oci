// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetSqlFirewallAllowedSqlArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSqlFirewallAllowedSqlArgs Empty = new GetSqlFirewallAllowedSqlArgs();

    /**
     * The OCID of the sqlFirewallAllowedSql resource.
     * 
     */
    @Import(name="sqlFirewallAllowedSqlId", required=true)
    private Output<String> sqlFirewallAllowedSqlId;

    /**
     * @return The OCID of the sqlFirewallAllowedSql resource.
     * 
     */
    public Output<String> sqlFirewallAllowedSqlId() {
        return this.sqlFirewallAllowedSqlId;
    }

    private GetSqlFirewallAllowedSqlArgs() {}

    private GetSqlFirewallAllowedSqlArgs(GetSqlFirewallAllowedSqlArgs $) {
        this.sqlFirewallAllowedSqlId = $.sqlFirewallAllowedSqlId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSqlFirewallAllowedSqlArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSqlFirewallAllowedSqlArgs $;

        public Builder() {
            $ = new GetSqlFirewallAllowedSqlArgs();
        }

        public Builder(GetSqlFirewallAllowedSqlArgs defaults) {
            $ = new GetSqlFirewallAllowedSqlArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param sqlFirewallAllowedSqlId The OCID of the sqlFirewallAllowedSql resource.
         * 
         * @return builder
         * 
         */
        public Builder sqlFirewallAllowedSqlId(Output<String> sqlFirewallAllowedSqlId) {
            $.sqlFirewallAllowedSqlId = sqlFirewallAllowedSqlId;
            return this;
        }

        /**
         * @param sqlFirewallAllowedSqlId The OCID of the sqlFirewallAllowedSql resource.
         * 
         * @return builder
         * 
         */
        public Builder sqlFirewallAllowedSqlId(String sqlFirewallAllowedSqlId) {
            return sqlFirewallAllowedSqlId(Output.of(sqlFirewallAllowedSqlId));
        }

        public GetSqlFirewallAllowedSqlArgs build() {
            if ($.sqlFirewallAllowedSqlId == null) {
                throw new MissingRequiredPropertyException("GetSqlFirewallAllowedSqlArgs", "sqlFirewallAllowedSqlId");
            }
            return $;
        }
    }

}
