// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class SoftwareSourceAssociatedManagedInstanceArgs extends com.pulumi.resources.ResourceArgs {

    public static final SoftwareSourceAssociatedManagedInstanceArgs Empty = new SoftwareSourceAssociatedManagedInstanceArgs();

    /**
     * (Updatable) User friendly name for the software source
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) User friendly name for the software source
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * OCID for the Software Source
     * 
     */
    @Import(name="id")
    private @Nullable Output<String> id;

    /**
     * @return OCID for the Software Source
     * 
     */
    public Optional<Output<String>> id() {
        return Optional.ofNullable(this.id);
    }

    private SoftwareSourceAssociatedManagedInstanceArgs() {}

    private SoftwareSourceAssociatedManagedInstanceArgs(SoftwareSourceAssociatedManagedInstanceArgs $) {
        this.displayName = $.displayName;
        this.id = $.id;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(SoftwareSourceAssociatedManagedInstanceArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private SoftwareSourceAssociatedManagedInstanceArgs $;

        public Builder() {
            $ = new SoftwareSourceAssociatedManagedInstanceArgs();
        }

        public Builder(SoftwareSourceAssociatedManagedInstanceArgs defaults) {
            $ = new SoftwareSourceAssociatedManagedInstanceArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param displayName (Updatable) User friendly name for the software source
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) User friendly name for the software source
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param id OCID for the Software Source
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable Output<String> id) {
            $.id = id;
            return this;
        }

        /**
         * @param id OCID for the Software Source
         * 
         * @return builder
         * 
         */
        public Builder id(String id) {
            return id(Output.of(id));
        }

        public SoftwareSourceAssociatedManagedInstanceArgs build() {
            return $;
        }
    }

}