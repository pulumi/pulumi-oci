// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseTools.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class DatabaseToolsConnectionRelatedResourceArgs extends com.pulumi.resources.ResourceArgs {

    public static final DatabaseToolsConnectionRelatedResourceArgs Empty = new DatabaseToolsConnectionRelatedResourceArgs();

    /**
     * (Updatable) The resource entity type.
     * 
     */
    @Import(name="entityType", required=true)
    private Output<String> entityType;

    /**
     * @return (Updatable) The resource entity type.
     * 
     */
    public Output<String> entityType() {
        return this.entityType;
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the related resource.
     * 
     */
    @Import(name="identifier", required=true)
    private Output<String> identifier;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the related resource.
     * 
     */
    public Output<String> identifier() {
        return this.identifier;
    }

    private DatabaseToolsConnectionRelatedResourceArgs() {}

    private DatabaseToolsConnectionRelatedResourceArgs(DatabaseToolsConnectionRelatedResourceArgs $) {
        this.entityType = $.entityType;
        this.identifier = $.identifier;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DatabaseToolsConnectionRelatedResourceArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DatabaseToolsConnectionRelatedResourceArgs $;

        public Builder() {
            $ = new DatabaseToolsConnectionRelatedResourceArgs();
        }

        public Builder(DatabaseToolsConnectionRelatedResourceArgs defaults) {
            $ = new DatabaseToolsConnectionRelatedResourceArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param entityType (Updatable) The resource entity type.
         * 
         * @return builder
         * 
         */
        public Builder entityType(Output<String> entityType) {
            $.entityType = entityType;
            return this;
        }

        /**
         * @param entityType (Updatable) The resource entity type.
         * 
         * @return builder
         * 
         */
        public Builder entityType(String entityType) {
            return entityType(Output.of(entityType));
        }

        /**
         * @param identifier (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the related resource.
         * 
         * @return builder
         * 
         */
        public Builder identifier(Output<String> identifier) {
            $.identifier = identifier;
            return this;
        }

        /**
         * @param identifier (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the related resource.
         * 
         * @return builder
         * 
         */
        public Builder identifier(String identifier) {
            return identifier(Output.of(identifier));
        }

        public DatabaseToolsConnectionRelatedResourceArgs build() {
            $.entityType = Objects.requireNonNull($.entityType, "expected parameter 'entityType' to be non-null");
            $.identifier = Objects.requireNonNull($.identifier, "expected parameter 'identifier' to be non-null");
            return $;
        }
    }

}