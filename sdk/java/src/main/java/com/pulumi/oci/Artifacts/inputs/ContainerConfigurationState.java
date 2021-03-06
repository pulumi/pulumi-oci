// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Artifacts.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ContainerConfigurationState extends com.pulumi.resources.ResourceArgs {

    public static final ContainerConfigurationState Empty = new ContainerConfigurationState();

    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * Whether to create a new container repository when a container is pushed to a new repository path. Repositories created in this way belong to the root compartment.
     * 
     */
    @Import(name="isRepositoryCreatedOnFirstPush")
    private @Nullable Output<Boolean> isRepositoryCreatedOnFirstPush;

    /**
     * @return Whether to create a new container repository when a container is pushed to a new repository path. Repositories created in this way belong to the root compartment.
     * 
     */
    public Optional<Output<Boolean>> isRepositoryCreatedOnFirstPush() {
        return Optional.ofNullable(this.isRepositoryCreatedOnFirstPush);
    }

    /**
     * The tenancy namespace used in the container repository path.
     * 
     */
    @Import(name="namespace")
    private @Nullable Output<String> namespace;

    /**
     * @return The tenancy namespace used in the container repository path.
     * 
     */
    public Optional<Output<String>> namespace() {
        return Optional.ofNullable(this.namespace);
    }

    private ContainerConfigurationState() {}

    private ContainerConfigurationState(ContainerConfigurationState $) {
        this.compartmentId = $.compartmentId;
        this.isRepositoryCreatedOnFirstPush = $.isRepositoryCreatedOnFirstPush;
        this.namespace = $.namespace;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ContainerConfigurationState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ContainerConfigurationState $;

        public Builder() {
            $ = new ContainerConfigurationState();
        }

        public Builder(ContainerConfigurationState defaults) {
            $ = new ContainerConfigurationState(Objects.requireNonNull(defaults));
        }

        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param isRepositoryCreatedOnFirstPush Whether to create a new container repository when a container is pushed to a new repository path. Repositories created in this way belong to the root compartment.
         * 
         * @return builder
         * 
         */
        public Builder isRepositoryCreatedOnFirstPush(@Nullable Output<Boolean> isRepositoryCreatedOnFirstPush) {
            $.isRepositoryCreatedOnFirstPush = isRepositoryCreatedOnFirstPush;
            return this;
        }

        /**
         * @param isRepositoryCreatedOnFirstPush Whether to create a new container repository when a container is pushed to a new repository path. Repositories created in this way belong to the root compartment.
         * 
         * @return builder
         * 
         */
        public Builder isRepositoryCreatedOnFirstPush(Boolean isRepositoryCreatedOnFirstPush) {
            return isRepositoryCreatedOnFirstPush(Output.of(isRepositoryCreatedOnFirstPush));
        }

        /**
         * @param namespace The tenancy namespace used in the container repository path.
         * 
         * @return builder
         * 
         */
        public Builder namespace(@Nullable Output<String> namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param namespace The tenancy namespace used in the container repository path.
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            return namespace(Output.of(namespace));
        }

        public ContainerConfigurationState build() {
            return $;
        }
    }

}
