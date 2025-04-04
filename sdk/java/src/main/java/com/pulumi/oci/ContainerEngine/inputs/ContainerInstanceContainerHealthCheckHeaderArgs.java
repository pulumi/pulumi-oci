// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ContainerInstanceContainerHealthCheckHeaderArgs extends com.pulumi.resources.ResourceArgs {

    public static final ContainerInstanceContainerHealthCheckHeaderArgs Empty = new ContainerInstanceContainerHealthCheckHeaderArgs();

    /**
     * Container HTTP header Key.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return Container HTTP header Key.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * Container HTTP header value.
     * 
     */
    @Import(name="value")
    private @Nullable Output<String> value;

    /**
     * @return Container HTTP header value.
     * 
     */
    public Optional<Output<String>> value() {
        return Optional.ofNullable(this.value);
    }

    private ContainerInstanceContainerHealthCheckHeaderArgs() {}

    private ContainerInstanceContainerHealthCheckHeaderArgs(ContainerInstanceContainerHealthCheckHeaderArgs $) {
        this.name = $.name;
        this.value = $.value;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ContainerInstanceContainerHealthCheckHeaderArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ContainerInstanceContainerHealthCheckHeaderArgs $;

        public Builder() {
            $ = new ContainerInstanceContainerHealthCheckHeaderArgs();
        }

        public Builder(ContainerInstanceContainerHealthCheckHeaderArgs defaults) {
            $ = new ContainerInstanceContainerHealthCheckHeaderArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param name Container HTTP header Key.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name Container HTTP header Key.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param value Container HTTP header value.
         * 
         * @return builder
         * 
         */
        public Builder value(@Nullable Output<String> value) {
            $.value = value;
            return this;
        }

        /**
         * @param value Container HTTP header value.
         * 
         * @return builder
         * 
         */
        public Builder value(String value) {
            return value(Output.of(value));
        }

        public ContainerInstanceContainerHealthCheckHeaderArgs build() {
            return $;
        }
    }

}
