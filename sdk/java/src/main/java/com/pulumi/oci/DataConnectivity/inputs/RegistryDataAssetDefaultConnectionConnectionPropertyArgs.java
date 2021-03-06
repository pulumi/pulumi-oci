// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataConnectivity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class RegistryDataAssetDefaultConnectionConnectionPropertyArgs extends com.pulumi.resources.ResourceArgs {

    public static final RegistryDataAssetDefaultConnectionConnectionPropertyArgs Empty = new RegistryDataAssetDefaultConnectionConnectionPropertyArgs();

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
     * (Updatable) The value for the connection name property.
     * 
     */
    @Import(name="value")
    private @Nullable Output<String> value;

    /**
     * @return (Updatable) The value for the connection name property.
     * 
     */
    public Optional<Output<String>> value() {
        return Optional.ofNullable(this.value);
    }

    private RegistryDataAssetDefaultConnectionConnectionPropertyArgs() {}

    private RegistryDataAssetDefaultConnectionConnectionPropertyArgs(RegistryDataAssetDefaultConnectionConnectionPropertyArgs $) {
        this.name = $.name;
        this.value = $.value;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(RegistryDataAssetDefaultConnectionConnectionPropertyArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private RegistryDataAssetDefaultConnectionConnectionPropertyArgs $;

        public Builder() {
            $ = new RegistryDataAssetDefaultConnectionConnectionPropertyArgs();
        }

        public Builder(RegistryDataAssetDefaultConnectionConnectionPropertyArgs defaults) {
            $ = new RegistryDataAssetDefaultConnectionConnectionPropertyArgs(Objects.requireNonNull(defaults));
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
         * @param value (Updatable) The value for the connection name property.
         * 
         * @return builder
         * 
         */
        public Builder value(@Nullable Output<String> value) {
            $.value = value;
            return this;
        }

        /**
         * @param value (Updatable) The value for the connection name property.
         * 
         * @return builder
         * 
         */
        public Builder value(String value) {
            return value(Output.of(value));
        }

        public RegistryDataAssetDefaultConnectionConnectionPropertyArgs build() {
            return $;
        }
    }

}
