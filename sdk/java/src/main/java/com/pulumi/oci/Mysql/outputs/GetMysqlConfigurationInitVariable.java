// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetMysqlConfigurationInitVariable {
    /**
     * @return Represents the MySQL server system variable lower_case_table_names (https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html#sysvar_lower_case_table_names).
     * 
     */
    private String lowerCaseTableNames;

    private GetMysqlConfigurationInitVariable() {}
    /**
     * @return Represents the MySQL server system variable lower_case_table_names (https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html#sysvar_lower_case_table_names).
     * 
     */
    public String lowerCaseTableNames() {
        return this.lowerCaseTableNames;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMysqlConfigurationInitVariable defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String lowerCaseTableNames;
        public Builder() {}
        public Builder(GetMysqlConfigurationInitVariable defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.lowerCaseTableNames = defaults.lowerCaseTableNames;
        }

        @CustomType.Setter
        public Builder lowerCaseTableNames(String lowerCaseTableNames) {
            this.lowerCaseTableNames = Objects.requireNonNull(lowerCaseTableNames);
            return this;
        }
        public GetMysqlConfigurationInitVariable build() {
            final var o = new GetMysqlConfigurationInitVariable();
            o.lowerCaseTableNames = lowerCaseTableNames;
            return o;
        }
    }
}