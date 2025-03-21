// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class ImportStandardTagsManagementArgs extends com.pulumi.resources.ResourceArgs {

    public static final ImportStandardTagsManagementArgs Empty = new ImportStandardTagsManagementArgs();

    /**
     * The OCID of the compartment where the bulk create request is submitted and where the tag namespaces will be created.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The OCID of the compartment where the bulk create request is submitted and where the tag namespaces will be created.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * The name of standard tag namespace that will be imported in bulk
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="standardTagNamespaceName", required=true)
    private Output<String> standardTagNamespaceName;

    /**
     * @return The name of standard tag namespace that will be imported in bulk
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> standardTagNamespaceName() {
        return this.standardTagNamespaceName;
    }

    private ImportStandardTagsManagementArgs() {}

    private ImportStandardTagsManagementArgs(ImportStandardTagsManagementArgs $) {
        this.compartmentId = $.compartmentId;
        this.standardTagNamespaceName = $.standardTagNamespaceName;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ImportStandardTagsManagementArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ImportStandardTagsManagementArgs $;

        public Builder() {
            $ = new ImportStandardTagsManagementArgs();
        }

        public Builder(ImportStandardTagsManagementArgs defaults) {
            $ = new ImportStandardTagsManagementArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the compartment where the bulk create request is submitted and where the tag namespaces will be created.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the compartment where the bulk create request is submitted and where the tag namespaces will be created.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param standardTagNamespaceName The name of standard tag namespace that will be imported in bulk
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder standardTagNamespaceName(Output<String> standardTagNamespaceName) {
            $.standardTagNamespaceName = standardTagNamespaceName;
            return this;
        }

        /**
         * @param standardTagNamespaceName The name of standard tag namespace that will be imported in bulk
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder standardTagNamespaceName(String standardTagNamespaceName) {
            return standardTagNamespaceName(Output.of(standardTagNamespaceName));
        }

        public ImportStandardTagsManagementArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("ImportStandardTagsManagementArgs", "compartmentId");
            }
            if ($.standardTagNamespaceName == null) {
                throw new MissingRequiredPropertyException("ImportStandardTagsManagementArgs", "standardTagNamespaceName");
            }
            return $;
        }
    }

}
