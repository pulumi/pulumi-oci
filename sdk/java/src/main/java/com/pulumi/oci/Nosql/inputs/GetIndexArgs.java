// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Nosql.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetIndexArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetIndexArgs Empty = new GetIndexArgs();

    /**
     * The ID of a table&#39;s compartment. When a table is identified by name, the compartmentId is often needed to provide context for interpreting the name.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The ID of a table&#39;s compartment. When a table is identified by name, the compartmentId is often needed to provide context for interpreting the name.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * The name of a table&#39;s index.
     * 
     */
    @Import(name="indexName", required=true)
    private Output<String> indexName;

    /**
     * @return The name of a table&#39;s index.
     * 
     */
    public Output<String> indexName() {
        return this.indexName;
    }

    /**
     * A table name within the compartment, or a table OCID.
     * 
     */
    @Import(name="tableNameOrId", required=true)
    private Output<String> tableNameOrId;

    /**
     * @return A table name within the compartment, or a table OCID.
     * 
     */
    public Output<String> tableNameOrId() {
        return this.tableNameOrId;
    }

    private GetIndexArgs() {}

    private GetIndexArgs(GetIndexArgs $) {
        this.compartmentId = $.compartmentId;
        this.indexName = $.indexName;
        this.tableNameOrId = $.tableNameOrId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetIndexArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetIndexArgs $;

        public Builder() {
            $ = new GetIndexArgs();
        }

        public Builder(GetIndexArgs defaults) {
            $ = new GetIndexArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The ID of a table&#39;s compartment. When a table is identified by name, the compartmentId is often needed to provide context for interpreting the name.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The ID of a table&#39;s compartment. When a table is identified by name, the compartmentId is often needed to provide context for interpreting the name.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param indexName The name of a table&#39;s index.
         * 
         * @return builder
         * 
         */
        public Builder indexName(Output<String> indexName) {
            $.indexName = indexName;
            return this;
        }

        /**
         * @param indexName The name of a table&#39;s index.
         * 
         * @return builder
         * 
         */
        public Builder indexName(String indexName) {
            return indexName(Output.of(indexName));
        }

        /**
         * @param tableNameOrId A table name within the compartment, or a table OCID.
         * 
         * @return builder
         * 
         */
        public Builder tableNameOrId(Output<String> tableNameOrId) {
            $.tableNameOrId = tableNameOrId;
            return this;
        }

        /**
         * @param tableNameOrId A table name within the compartment, or a table OCID.
         * 
         * @return builder
         * 
         */
        public Builder tableNameOrId(String tableNameOrId) {
            return tableNameOrId(Output.of(tableNameOrId));
        }

        public GetIndexArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetIndexArgs", "compartmentId");
            }
            if ($.indexName == null) {
                throw new MissingRequiredPropertyException("GetIndexArgs", "indexName");
            }
            if ($.tableNameOrId == null) {
                throw new MissingRequiredPropertyException("GetIndexArgs", "tableNameOrId");
            }
            return $;
        }
    }

}
