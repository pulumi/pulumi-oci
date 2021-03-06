// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataConnectivity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class RegistryConnectionPrimarySchemaMetadataAggregatorArgs extends com.pulumi.resources.ResourceArgs {

    public static final RegistryConnectionPrimarySchemaMetadataAggregatorArgs Empty = new RegistryConnectionPrimarySchemaMetadataAggregatorArgs();

    /**
     * (Updatable) The description of the aggregator.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) The description of the aggregator.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) The identifier of the aggregator.
     * 
     */
    @Import(name="identifier")
    private @Nullable Output<String> identifier;

    /**
     * @return (Updatable) The identifier of the aggregator.
     * 
     */
    public Optional<Output<String>> identifier() {
        return Optional.ofNullable(this.identifier);
    }

    /**
     * (Updatable) The identifying key for the object.
     * 
     */
    @Import(name="key")
    private @Nullable Output<String> key;

    /**
     * @return (Updatable) The identifying key for the object.
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
     * (Updatable) Specific Connection Type
     * 
     */
    @Import(name="type")
    private @Nullable Output<String> type;

    /**
     * @return (Updatable) Specific Connection Type
     * 
     */
    public Optional<Output<String>> type() {
        return Optional.ofNullable(this.type);
    }

    private RegistryConnectionPrimarySchemaMetadataAggregatorArgs() {}

    private RegistryConnectionPrimarySchemaMetadataAggregatorArgs(RegistryConnectionPrimarySchemaMetadataAggregatorArgs $) {
        this.description = $.description;
        this.identifier = $.identifier;
        this.key = $.key;
        this.name = $.name;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(RegistryConnectionPrimarySchemaMetadataAggregatorArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private RegistryConnectionPrimarySchemaMetadataAggregatorArgs $;

        public Builder() {
            $ = new RegistryConnectionPrimarySchemaMetadataAggregatorArgs();
        }

        public Builder(RegistryConnectionPrimarySchemaMetadataAggregatorArgs defaults) {
            $ = new RegistryConnectionPrimarySchemaMetadataAggregatorArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param description (Updatable) The description of the aggregator.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) The description of the aggregator.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param identifier (Updatable) The identifier of the aggregator.
         * 
         * @return builder
         * 
         */
        public Builder identifier(@Nullable Output<String> identifier) {
            $.identifier = identifier;
            return this;
        }

        /**
         * @param identifier (Updatable) The identifier of the aggregator.
         * 
         * @return builder
         * 
         */
        public Builder identifier(String identifier) {
            return identifier(Output.of(identifier));
        }

        /**
         * @param key (Updatable) The identifying key for the object.
         * 
         * @return builder
         * 
         */
        public Builder key(@Nullable Output<String> key) {
            $.key = key;
            return this;
        }

        /**
         * @param key (Updatable) The identifying key for the object.
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
         * @param type (Updatable) Specific Connection Type
         * 
         * @return builder
         * 
         */
        public Builder type(@Nullable Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type (Updatable) Specific Connection Type
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        public RegistryConnectionPrimarySchemaMetadataAggregatorArgs build() {
            return $;
        }
    }

}
