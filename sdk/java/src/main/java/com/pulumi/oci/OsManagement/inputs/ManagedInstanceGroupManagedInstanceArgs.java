// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ManagedInstanceGroupManagedInstanceArgs extends com.pulumi.resources.ResourceArgs {

    public static final ManagedInstanceGroupManagedInstanceArgs Empty = new ManagedInstanceGroupManagedInstanceArgs();

    /**
     * (Updatable) Managed Instance Group identifier
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) Managed Instance Group identifier
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * unique identifier that is immutable on creation
     * 
     */
    @Import(name="id")
    private @Nullable Output<String> id;

    /**
     * @return unique identifier that is immutable on creation
     * 
     */
    public Optional<Output<String>> id() {
        return Optional.ofNullable(this.id);
    }

    private ManagedInstanceGroupManagedInstanceArgs() {}

    private ManagedInstanceGroupManagedInstanceArgs(ManagedInstanceGroupManagedInstanceArgs $) {
        this.displayName = $.displayName;
        this.id = $.id;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ManagedInstanceGroupManagedInstanceArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ManagedInstanceGroupManagedInstanceArgs $;

        public Builder() {
            $ = new ManagedInstanceGroupManagedInstanceArgs();
        }

        public Builder(ManagedInstanceGroupManagedInstanceArgs defaults) {
            $ = new ManagedInstanceGroupManagedInstanceArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param displayName (Updatable) Managed Instance Group identifier
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) Managed Instance Group identifier
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param id unique identifier that is immutable on creation
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable Output<String> id) {
            $.id = id;
            return this;
        }

        /**
         * @param id unique identifier that is immutable on creation
         * 
         * @return builder
         * 
         */
        public Builder id(String id) {
            return id(Output.of(id));
        }

        public ManagedInstanceGroupManagedInstanceArgs build() {
            return $;
        }
    }

}
