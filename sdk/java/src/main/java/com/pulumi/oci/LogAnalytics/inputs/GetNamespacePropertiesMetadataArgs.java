// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.LogAnalytics.inputs.GetNamespacePropertiesMetadataFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetNamespacePropertiesMetadataArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetNamespacePropertiesMetadataArgs Empty = new GetNamespacePropertiesMetadataArgs();

    /**
     * The constraints that apply to the properties at a certain level.
     * 
     */
    @Import(name="constraints")
    private @Nullable Output<String> constraints;

    /**
     * @return The constraints that apply to the properties at a certain level.
     * 
     */
    public Optional<Output<String>> constraints() {
        return Optional.ofNullable(this.constraints);
    }

    /**
     * The property display text used for filtering. Only properties matching the specified display name or description will be returned.
     * 
     */
    @Import(name="displayText")
    private @Nullable Output<String> displayText;

    /**
     * @return The property display text used for filtering. Only properties matching the specified display name or description will be returned.
     * 
     */
    public Optional<Output<String>> displayText() {
        return Optional.ofNullable(this.displayText);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetNamespacePropertiesMetadataFilterArgs>> filters;

    public Optional<Output<List<GetNamespacePropertiesMetadataFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The level for which applicable properties are to be listed.
     * 
     */
    @Import(name="level")
    private @Nullable Output<String> level;

    /**
     * @return The level for which applicable properties are to be listed.
     * 
     */
    public Optional<Output<String>> level() {
        return Optional.ofNullable(this.level);
    }

    /**
     * The property name used for filtering.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return The property name used for filtering.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * The Logging Analytics namespace used for the request.
     * 
     */
    @Import(name="namespace", required=true)
    private Output<String> namespace;

    /**
     * @return The Logging Analytics namespace used for the request.
     * 
     */
    public Output<String> namespace() {
        return this.namespace;
    }

    private GetNamespacePropertiesMetadataArgs() {}

    private GetNamespacePropertiesMetadataArgs(GetNamespacePropertiesMetadataArgs $) {
        this.constraints = $.constraints;
        this.displayText = $.displayText;
        this.filters = $.filters;
        this.level = $.level;
        this.name = $.name;
        this.namespace = $.namespace;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetNamespacePropertiesMetadataArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetNamespacePropertiesMetadataArgs $;

        public Builder() {
            $ = new GetNamespacePropertiesMetadataArgs();
        }

        public Builder(GetNamespacePropertiesMetadataArgs defaults) {
            $ = new GetNamespacePropertiesMetadataArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param constraints The constraints that apply to the properties at a certain level.
         * 
         * @return builder
         * 
         */
        public Builder constraints(@Nullable Output<String> constraints) {
            $.constraints = constraints;
            return this;
        }

        /**
         * @param constraints The constraints that apply to the properties at a certain level.
         * 
         * @return builder
         * 
         */
        public Builder constraints(String constraints) {
            return constraints(Output.of(constraints));
        }

        /**
         * @param displayText The property display text used for filtering. Only properties matching the specified display name or description will be returned.
         * 
         * @return builder
         * 
         */
        public Builder displayText(@Nullable Output<String> displayText) {
            $.displayText = displayText;
            return this;
        }

        /**
         * @param displayText The property display text used for filtering. Only properties matching the specified display name or description will be returned.
         * 
         * @return builder
         * 
         */
        public Builder displayText(String displayText) {
            return displayText(Output.of(displayText));
        }

        public Builder filters(@Nullable Output<List<GetNamespacePropertiesMetadataFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetNamespacePropertiesMetadataFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetNamespacePropertiesMetadataFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param level The level for which applicable properties are to be listed.
         * 
         * @return builder
         * 
         */
        public Builder level(@Nullable Output<String> level) {
            $.level = level;
            return this;
        }

        /**
         * @param level The level for which applicable properties are to be listed.
         * 
         * @return builder
         * 
         */
        public Builder level(String level) {
            return level(Output.of(level));
        }

        /**
         * @param name The property name used for filtering.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name The property name used for filtering.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param namespace The Logging Analytics namespace used for the request.
         * 
         * @return builder
         * 
         */
        public Builder namespace(Output<String> namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param namespace The Logging Analytics namespace used for the request.
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            return namespace(Output.of(namespace));
        }

        public GetNamespacePropertiesMetadataArgs build() {
            if ($.namespace == null) {
                throw new MissingRequiredPropertyException("GetNamespacePropertiesMetadataArgs", "namespace");
            }
            return $;
        }
    }

}
