// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Nosql.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetIndexPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetIndexPlainArgs Empty = new GetIndexPlainArgs();

    /**
     * The ID of a table&#39;s compartment. When a table is identified by name, the compartmentId is often needed to provide context for interpreting the name.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The ID of a table&#39;s compartment. When a table is identified by name, the compartmentId is often needed to provide context for interpreting the name.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    /**
     * The name of a table&#39;s index.
     * 
     */
    @Import(name="indexName", required=true)
    private String indexName;

    /**
     * @return The name of a table&#39;s index.
     * 
     */
    public String indexName() {
        return this.indexName;
    }

    /**
     * A table name within the compartment, or a table OCID.
     * 
     */
    @Import(name="tableNameOrId", required=true)
    private String tableNameOrId;

    /**
     * @return A table name within the compartment, or a table OCID.
     * 
     */
    public String tableNameOrId() {
        return this.tableNameOrId;
    }

    private GetIndexPlainArgs() {}

    private GetIndexPlainArgs(GetIndexPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.indexName = $.indexName;
        this.tableNameOrId = $.tableNameOrId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetIndexPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetIndexPlainArgs $;

        public Builder() {
            $ = new GetIndexPlainArgs();
        }

        public Builder(GetIndexPlainArgs defaults) {
            $ = new GetIndexPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The ID of a table&#39;s compartment. When a table is identified by name, the compartmentId is often needed to provide context for interpreting the name.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param indexName The name of a table&#39;s index.
         * 
         * @return builder
         * 
         */
        public Builder indexName(String indexName) {
            $.indexName = indexName;
            return this;
        }

        /**
         * @param tableNameOrId A table name within the compartment, or a table OCID.
         * 
         * @return builder
         * 
         */
        public Builder tableNameOrId(String tableNameOrId) {
            $.tableNameOrId = tableNameOrId;
            return this;
        }

        public GetIndexPlainArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.indexName = Objects.requireNonNull($.indexName, "expected parameter 'indexName' to be non-null");
            $.tableNameOrId = Objects.requireNonNull($.tableNameOrId, "expected parameter 'tableNameOrId' to be non-null");
            return $;
        }
    }

}