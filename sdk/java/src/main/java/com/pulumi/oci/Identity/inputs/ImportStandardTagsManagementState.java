// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ImportStandardTagsManagementState extends com.pulumi.resources.ResourceArgs {

    public static final ImportStandardTagsManagementState Empty = new ImportStandardTagsManagementState();

    /**
     * The OCID of the compartment where the bulk create request is submitted and where the tag namespaces will be created.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The OCID of the compartment where the bulk create request is submitted and where the tag namespaces will be created.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * The name of standard tag namespace that will be imported in bulk
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="standardTagNamespaceName")
    private @Nullable Output<String> standardTagNamespaceName;

    /**
     * @return The name of standard tag namespace that will be imported in bulk
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> standardTagNamespaceName() {
        return Optional.ofNullable(this.standardTagNamespaceName);
    }

    @Import(name="workRequestId")
    private @Nullable Output<String> workRequestId;

    public Optional<Output<String>> workRequestId() {
        return Optional.ofNullable(this.workRequestId);
    }

    private ImportStandardTagsManagementState() {}

    private ImportStandardTagsManagementState(ImportStandardTagsManagementState $) {
        this.compartmentId = $.compartmentId;
        this.standardTagNamespaceName = $.standardTagNamespaceName;
        this.workRequestId = $.workRequestId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ImportStandardTagsManagementState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ImportStandardTagsManagementState $;

        public Builder() {
            $ = new ImportStandardTagsManagementState();
        }

        public Builder(ImportStandardTagsManagementState defaults) {
            $ = new ImportStandardTagsManagementState(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the compartment where the bulk create request is submitted and where the tag namespaces will be created.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
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
        public Builder standardTagNamespaceName(@Nullable Output<String> standardTagNamespaceName) {
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

        public Builder workRequestId(@Nullable Output<String> workRequestId) {
            $.workRequestId = workRequestId;
            return this;
        }

        public Builder workRequestId(String workRequestId) {
            return workRequestId(Output.of(workRequestId));
        }

        public ImportStandardTagsManagementState build() {
            return $;
        }
    }

}
