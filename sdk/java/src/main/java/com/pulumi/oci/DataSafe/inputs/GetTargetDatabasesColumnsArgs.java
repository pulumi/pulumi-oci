// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DataSafe.inputs.GetTargetDatabasesColumnsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetTargetDatabasesColumnsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetTargetDatabasesColumnsArgs Empty = new GetTargetDatabasesColumnsArgs();

    /**
     * A filter to return only items if column name contains a specific string.
     * 
     */
    @Import(name="columnNameContains")
    private @Nullable Output<String> columnNameContains;

    /**
     * @return A filter to return only items if column name contains a specific string.
     * 
     */
    public Optional<Output<String>> columnNameContains() {
        return Optional.ofNullable(this.columnNameContains);
    }

    /**
     * A filter to return only a specific column based on column name.
     * 
     */
    @Import(name="columnNames")
    private @Nullable Output<List<String>> columnNames;

    /**
     * @return A filter to return only a specific column based on column name.
     * 
     */
    public Optional<Output<List<String>>> columnNames() {
        return Optional.ofNullable(this.columnNames);
    }

    /**
     * A filter to return only items related to specific datatype.
     * 
     */
    @Import(name="datatypes")
    private @Nullable Output<List<String>> datatypes;

    /**
     * @return A filter to return only items related to specific datatype.
     * 
     */
    public Optional<Output<List<String>>> datatypes() {
        return Optional.ofNullable(this.datatypes);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetTargetDatabasesColumnsFilterArgs>> filters;

    public Optional<Output<List<GetTargetDatabasesColumnsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only items if schema name contains a specific string.
     * 
     */
    @Import(name="schemaNameContains")
    private @Nullable Output<String> schemaNameContains;

    /**
     * @return A filter to return only items if schema name contains a specific string.
     * 
     */
    public Optional<Output<String>> schemaNameContains() {
        return Optional.ofNullable(this.schemaNameContains);
    }

    /**
     * A filter to return only items related to specific schema name.
     * 
     */
    @Import(name="schemaNames")
    private @Nullable Output<List<String>> schemaNames;

    /**
     * @return A filter to return only items related to specific schema name.
     * 
     */
    public Optional<Output<List<String>>> schemaNames() {
        return Optional.ofNullable(this.schemaNames);
    }

    /**
     * A filter to return only items if table name contains a specific string.
     * 
     */
    @Import(name="tableNameContains")
    private @Nullable Output<String> tableNameContains;

    /**
     * @return A filter to return only items if table name contains a specific string.
     * 
     */
    public Optional<Output<String>> tableNameContains() {
        return Optional.ofNullable(this.tableNameContains);
    }

    /**
     * A filter to return only items related to specific table name.
     * 
     */
    @Import(name="tableNames")
    private @Nullable Output<List<String>> tableNames;

    /**
     * @return A filter to return only items related to specific table name.
     * 
     */
    public Optional<Output<List<String>>> tableNames() {
        return Optional.ofNullable(this.tableNames);
    }

    /**
     * The OCID of the Data Safe target database.
     * 
     */
    @Import(name="targetDatabaseId", required=true)
    private Output<String> targetDatabaseId;

    /**
     * @return The OCID of the Data Safe target database.
     * 
     */
    public Output<String> targetDatabaseId() {
        return this.targetDatabaseId;
    }

    private GetTargetDatabasesColumnsArgs() {}

    private GetTargetDatabasesColumnsArgs(GetTargetDatabasesColumnsArgs $) {
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
    public static Builder builder(GetTargetDatabasesColumnsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetTargetDatabasesColumnsArgs $;

        public Builder() {
            $ = new GetTargetDatabasesColumnsArgs();
        }

        public Builder(GetTargetDatabasesColumnsArgs defaults) {
            $ = new GetTargetDatabasesColumnsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param columnNameContains A filter to return only items if column name contains a specific string.
         * 
         * @return builder
         * 
         */
        public Builder columnNameContains(@Nullable Output<String> columnNameContains) {
            $.columnNameContains = columnNameContains;
            return this;
        }

        /**
         * @param columnNameContains A filter to return only items if column name contains a specific string.
         * 
         * @return builder
         * 
         */
        public Builder columnNameContains(String columnNameContains) {
            return columnNameContains(Output.of(columnNameContains));
        }

        /**
         * @param columnNames A filter to return only a specific column based on column name.
         * 
         * @return builder
         * 
         */
        public Builder columnNames(@Nullable Output<List<String>> columnNames) {
            $.columnNames = columnNames;
            return this;
        }

        /**
         * @param columnNames A filter to return only a specific column based on column name.
         * 
         * @return builder
         * 
         */
        public Builder columnNames(List<String> columnNames) {
            return columnNames(Output.of(columnNames));
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
        public Builder datatypes(@Nullable Output<List<String>> datatypes) {
            $.datatypes = datatypes;
            return this;
        }

        /**
         * @param datatypes A filter to return only items related to specific datatype.
         * 
         * @return builder
         * 
         */
        public Builder datatypes(List<String> datatypes) {
            return datatypes(Output.of(datatypes));
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

        public Builder filters(@Nullable Output<List<GetTargetDatabasesColumnsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetTargetDatabasesColumnsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetTargetDatabasesColumnsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param schemaNameContains A filter to return only items if schema name contains a specific string.
         * 
         * @return builder
         * 
         */
        public Builder schemaNameContains(@Nullable Output<String> schemaNameContains) {
            $.schemaNameContains = schemaNameContains;
            return this;
        }

        /**
         * @param schemaNameContains A filter to return only items if schema name contains a specific string.
         * 
         * @return builder
         * 
         */
        public Builder schemaNameContains(String schemaNameContains) {
            return schemaNameContains(Output.of(schemaNameContains));
        }

        /**
         * @param schemaNames A filter to return only items related to specific schema name.
         * 
         * @return builder
         * 
         */
        public Builder schemaNames(@Nullable Output<List<String>> schemaNames) {
            $.schemaNames = schemaNames;
            return this;
        }

        /**
         * @param schemaNames A filter to return only items related to specific schema name.
         * 
         * @return builder
         * 
         */
        public Builder schemaNames(List<String> schemaNames) {
            return schemaNames(Output.of(schemaNames));
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
        public Builder tableNameContains(@Nullable Output<String> tableNameContains) {
            $.tableNameContains = tableNameContains;
            return this;
        }

        /**
         * @param tableNameContains A filter to return only items if table name contains a specific string.
         * 
         * @return builder
         * 
         */
        public Builder tableNameContains(String tableNameContains) {
            return tableNameContains(Output.of(tableNameContains));
        }

        /**
         * @param tableNames A filter to return only items related to specific table name.
         * 
         * @return builder
         * 
         */
        public Builder tableNames(@Nullable Output<List<String>> tableNames) {
            $.tableNames = tableNames;
            return this;
        }

        /**
         * @param tableNames A filter to return only items related to specific table name.
         * 
         * @return builder
         * 
         */
        public Builder tableNames(List<String> tableNames) {
            return tableNames(Output.of(tableNames));
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
        public Builder targetDatabaseId(Output<String> targetDatabaseId) {
            $.targetDatabaseId = targetDatabaseId;
            return this;
        }

        /**
         * @param targetDatabaseId The OCID of the Data Safe target database.
         * 
         * @return builder
         * 
         */
        public Builder targetDatabaseId(String targetDatabaseId) {
            return targetDatabaseId(Output.of(targetDatabaseId));
        }

        public GetTargetDatabasesColumnsArgs build() {
            $.targetDatabaseId = Objects.requireNonNull($.targetDatabaseId, "expected parameter 'targetDatabaseId' to be non-null");
            return $;
        }
    }

}