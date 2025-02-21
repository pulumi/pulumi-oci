// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetSqlFirewallPolicyPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSqlFirewallPolicyPlainArgs Empty = new GetSqlFirewallPolicyPlainArgs();

    /**
     * The OCID of the SQL Firewall policy resource.
     * 
     */
    @Import(name="sqlFirewallPolicyId", required=true)
    private String sqlFirewallPolicyId;

    /**
     * @return The OCID of the SQL Firewall policy resource.
     * 
     */
    public String sqlFirewallPolicyId() {
        return this.sqlFirewallPolicyId;
    }

    private GetSqlFirewallPolicyPlainArgs() {}

    private GetSqlFirewallPolicyPlainArgs(GetSqlFirewallPolicyPlainArgs $) {
        this.sqlFirewallPolicyId = $.sqlFirewallPolicyId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSqlFirewallPolicyPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSqlFirewallPolicyPlainArgs $;

        public Builder() {
            $ = new GetSqlFirewallPolicyPlainArgs();
        }

        public Builder(GetSqlFirewallPolicyPlainArgs defaults) {
            $ = new GetSqlFirewallPolicyPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param sqlFirewallPolicyId The OCID of the SQL Firewall policy resource.
         * 
         * @return builder
         * 
         */
        public Builder sqlFirewallPolicyId(String sqlFirewallPolicyId) {
            $.sqlFirewallPolicyId = sqlFirewallPolicyId;
            return this;
        }

        public GetSqlFirewallPolicyPlainArgs build() {
            if ($.sqlFirewallPolicyId == null) {
                throw new MissingRequiredPropertyException("GetSqlFirewallPolicyPlainArgs", "sqlFirewallPolicyId");
            }
            return $;
        }
    }

}
