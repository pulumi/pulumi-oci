// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class WorkspaceApplicationMetadataAggregatorArgs extends com.pulumi.resources.ResourceArgs {

    public static final WorkspaceApplicationMetadataAggregatorArgs Empty = new WorkspaceApplicationMetadataAggregatorArgs();

    /**
     * (Updatable) Detailed description for the object.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) Detailed description for the object.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
     * 
     */
    @Import(name="identifier")
    private @Nullable Output<String> identifier;

    /**
     * @return (Updatable) Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
     * 
     */
    public Optional<Output<String>> identifier() {
        return Optional.ofNullable(this.identifier);
    }

    /**
     * The identifying key for the object.
     * 
     */
    @Import(name="key")
    private @Nullable Output<String> key;

    /**
     * @return The identifying key for the object.
     * 
     */
    public Optional<Output<String>> key() {
        return Optional.ofNullable(this.key);
    }

    /**
     * (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * The type of the object in patch.
     * 
     */
    @Import(name="type")
    private @Nullable Output<String> type;

    /**
     * @return The type of the object in patch.
     * 
     */
    public Optional<Output<String>> type() {
        return Optional.ofNullable(this.type);
    }

    private WorkspaceApplicationMetadataAggregatorArgs() {}

    private WorkspaceApplicationMetadataAggregatorArgs(WorkspaceApplicationMetadataAggregatorArgs $) {
        this.description = $.description;
        this.identifier = $.identifier;
        this.key = $.key;
        this.name = $.name;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(WorkspaceApplicationMetadataAggregatorArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private WorkspaceApplicationMetadataAggregatorArgs $;

        public Builder() {
            $ = new WorkspaceApplicationMetadataAggregatorArgs();
        }

        public Builder(WorkspaceApplicationMetadataAggregatorArgs defaults) {
            $ = new WorkspaceApplicationMetadataAggregatorArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param description (Updatable) Detailed description for the object.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) Detailed description for the object.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param identifier (Updatable) Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
         * 
         * @return builder
         * 
         */
        public Builder identifier(@Nullable Output<String> identifier) {
            $.identifier = identifier;
            return this;
        }

        /**
         * @param identifier (Updatable) Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
         * 
         * @return builder
         * 
         */
        public Builder identifier(String identifier) {
            return identifier(Output.of(identifier));
        }

        /**
         * @param key The identifying key for the object.
         * 
         * @return builder
         * 
         */
        public Builder key(@Nullable Output<String> key) {
            $.key = key;
            return this;
        }

        /**
         * @param key The identifying key for the object.
         * 
         * @return builder
         * 
         */
        public Builder key(String key) {
            return key(Output.of(key));
        }

        /**
         * @param name (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param type The type of the object in patch.
         * 
         * @return builder
         * 
         */
        public Builder type(@Nullable Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type The type of the object in patch.
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        public WorkspaceApplicationMetadataAggregatorArgs build() {
            return $;
        }
    }

}