// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DataSafe.inputs.GetTargetDatabasesColumnsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetTargetDatabasesColumnsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetTargetDatabasesColumnsPlainArgs Empty = new GetTargetDatabasesColumnsPlainArgs();

    /**
     * A filter to return only items if column name contains a specific string.
     * 
     */
    @Import(name="columnNameContains")
    private @Nullable String columnNameContains;

    /**
     * @return A filter to return only items if column name contains a specific string.
     * 
     */
    public Optional<String> columnNameContains() {
        return Optional.ofNullable(this.columnNameContains);
    }

    /**
     * A filter to return only a specific column based on column name.
     * 
     */
    @Import(name="columnNames")
    private @Nullable List<String> columnNames;

    /**
     * @return A filter to return only a specific column based on column name.
     * 
     */
    public Optional<List<String>> columnNames() {
        return Optional.ofNullable(this.columnNames);
    }

    /**
     * A filter to return only items related to specific datatype.
     * 
     */
    @Import(name="datatypes")
    private @Nullable List<String> datatypes;

    /**
     * @return A filter to return only items related to specific datatype.
     * 
     */
    public Optional<List<String>> datatypes() {
        return Optional.ofNullable(this.datatypes);
    }

    @Import(name="filters")
    private @Nullable List<GetTargetDatabasesColumnsFilter> filters;

    public Optional<List<GetTargetDatabasesColumnsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only items if schema name contains a specific string.
     * 
     */
    @Import(name="schemaNameContains")
    private @Nullable String schemaNameContains;

    /**
     * @return A filter to return only items if schema name contains a specific string.
     * 
     */
    public Optional<String> schemaNameContains() {
        return Optional.ofNullable(this.schemaNameContains);
    }

    /**
     * A filter to return only items related to specific schema name.
     * 
     */
    @Import(name="schemaNames")
    private @Nullable List<String> schemaNames;

    /**
     * @return A filter to return only items related to specific schema name.
     * 
     */
    public Optional<List<String>> schemaNames() {
        return Optional.ofNullable(this.schemaNames);
    }

    /**
     * A filter to return only items if table name contains a specific string.
     * 
     */
    @Import(name="tableNameContains")
    private @Nullable String tableNameContains;

    /**
     * @return A filter to return only items if table name contains a specific string.
     * 
     */
    public Optional<String> tableNameContains() {
        return Optional.ofNullable(this.tableNameContains);
    }

    /**
     * A filter to return only items related to specific table name.
     * 
     */
    @Import(name="tableNames")
    private @Nullable List<String> tableNames;

    /**
     * @return A filter to return only items related to specific table name.
     * 
     */
    public Optional<List<String>> tableNames() {
        return Optional.ofNullable(this.tableNames);
    }

    /**
     * The OCID of the Data Safe target database.
     * 
     */
    @Import(name="targetDatabaseId", required=true)
    private String targetDatabaseId;

    /**
     * @return The OCID of the Data Safe target database.
     * 
     */
    public String targetDatabaseId() {
        return this.targetDatabaseId;
    }

    private GetTargetDatabasesColumnsPlainArgs() {}

    private GetTargetDatabasesColumnsPlainArgs(GetTargetDatabasesColumnsPlainArgs $) {
        this.columnNameContains = $.columnNameContains;
        this.columnNames = $.columnNames;
        this.datatypes = $.datatypes;
        this.filters = $.filters;
        this.schemaNameContains = $.schemaNameContains;
        this.schemaNames = $.schemaNames;
        this.tableNameContains = $.tableNameContains;
        this.tableNames = $.tableNames;
        this.targetDatabaseId = $.targetDatabaseId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetTargetDatabasesColumnsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetTargetDatabasesColumnsPlainArgs $;

        public Builder() {
            $ = new GetTargetDatabasesColumnsPlainArgs();
        }

        public Builder(GetTargetDatabasesColumnsPlainArgs defaults) {
            $ = new GetTargetDatabasesColumnsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param columnNameContains A filter to return only items if column name contains a specific string.
         * 
         * @return builder
         * 
         */
        public Builder columnNameContains(@Nullable String columnNameContains) {
            $.columnNameContains = columnNameContains;
            return this;
        }

        /**
         * @param columnNames A filter to return only a specific column based on column name.
         * 
         * @return builder
         * 
         */
        public Builder columnNames(@Nullable List<String> columnNames) {
            $.columnNames = columnNames;
            return this;
        }

        /**
         * @param columnNames A filter to return only a specific column based on column name.
         * 
         * @return builder
         * 
         */
        public Builder columnNames(String... columnNames) {
            return columnNames(List.of(columnNames));
        }

        /**
         * @param datatypes A filter to return only items related to specific datatype.
         * 
         * @return builder
         * 
         */
        public Builder datatypes(@Nullable List<String> datatypes) {
            $.datatypes = datatypes;
            return this;
        }

        /**
         * @param datatypes A filter to return only items related to specific datatype.
         * 
         * @return builder
         * 
         */
        public Builder datatypes(String... datatypes) {
            return datatypes(List.of(datatypes));
        }

        public Builder filters(@Nullable List<GetTargetDatabasesColumnsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetTargetDatabasesColumnsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param schemaNameContains A filter to return only items if schema name contains a specific string.
         * 
         * @return builder
         * 
         */
        public Builder schemaNameContains(@Nullable String schemaNameContains) {
            $.schemaNameContains = schemaNameContains;
            return this;
        }

        /**
         * @param schemaNames A filter to return only items related to specific schema name.
         * 
         * @return builder
         * 
         */
        public Builder schemaNames(@Nullable List<String> schemaNames) {
            $.schemaNames = schemaNames;
            return this;
        }

        /**
         * @param schemaNames A filter to return only items related to specific schema name.
         * 
         * @return builder
         * 
         */
        public Builder schemaNames(String... schemaNames) {
            return schemaNames(List.of(schemaNames));
        }

        /**
         * @param tableNameContains A filter to return only items if table name contains a specific string.
         * 
         * @return builder
         * 
         */
        public Builder tableNameContains(@Nullable String tableNameContains) {
            $.tableNameContains = tableNameContains;
            return this;
        }

        /**
         * @param tableNames A filter to return only items related to specific table name.
         * 
         * @return builder
         * 
         */
        public Builder tableNames(@Nullable List<String> tableNames) {
            $.tableNames = tableNames;
            return this;
        }

        /**
         * @param tableNames A filter to return only items related to specific table name.
         * 
         * @return builder
         * 
         */
        public Builder tableNames(String... tableNames) {
            return tableNames(List.of(tableNames));
        }

        /**
         * @param targetDatabaseId The OCID of the Data Safe target database.
         * 
         * @return builder
         * 
         */
        public Builder targetDatabaseId(String targetDatabaseId) {
            $.targetDatabaseId = targetDatabaseId;
            return this;
        }

        public GetTargetDatabasesColumnsPlainArgs build() {
            $.targetDatabaseId = Objects.requireNonNull($.targetDatabaseId, "expected parameter 'targetDatabaseId' to be non-null");
            return $;
        }
    }

}