// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetTargetDatabasesTablesTable {
    /**
     * @return A filter to return only items related to specific schema name.
     * 
     */
    private String schemaName;
    /**
     * @return A filter to return only items related to specific table name.
     * 
     */
    private String tableName;

    private GetTargetDatabasesTablesTable() {}
    /**
     * @return A filter to return only items related to specific schema name.
     * 
     */
    public String schemaName() {
        return this.schemaName;
    }
    /**
     * @return A filter to return only items related to specific table name.
     * 
     */
    public String tableName() {
        return this.tableName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetTargetDatabasesTablesTable defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String schemaName;
        private String tableName;
        public Builder() {}
        public Builder(GetTargetDatabasesTablesTable defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.schemaName = defaults.schemaName;
    	      this.tableName = defaults.tableName;
        }

        @CustomType.Setter
        public Builder schemaName(String schemaName) {
            this.schemaName = Objects.requireNonNull(schemaName);
            return this;
        }
        @CustomType.Setter
        public Builder tableName(String tableName) {
            this.tableName = Objects.requireNonNull(tableName);
            return this;
        }
        public GetTargetDatabasesTablesTable build() {
            final var o = new GetTargetDatabasesTablesTable();
            o.schemaName = schemaName;
            o.tableName = tableName;
            return o;
        }
    }
}