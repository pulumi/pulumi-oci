// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Artifacts;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;


public final class ContainerConfigurationArgs extends com.pulumi.resources.ResourceArgs {

    public static final ContainerConfigurationArgs Empty = new ContainerConfigurationArgs();

    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * Whether to create a new container repository when a container is pushed to a new repository path. Repositories created in this way belong to the root compartment.
     * 
     */
    @Import(name="isRepositoryCreatedOnFirstPush", required=true)
    private Output<Boolean> isRepositoryCreatedOnFirstPush;

    /**
     * @return Whether to create a new container repository when a container is pushed to a new repository path. Repositories created in this way belong to the root compartment.
     * 
     */
    public Output<Boolean> isRepositoryCreatedOnFirstPush() {
        return this.isRepositoryCreatedOnFirstPush;
    }

    private ContainerConfigurationArgs() {}

    private ContainerConfigurationArgs(ContainerConfigurationArgs $) {
        this.compartmentId = $.compartmentId;
        this.isRepositoryCreatedOnFirstPush = $.isRepositoryCreatedOnFirstPush;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ContainerConfigurationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ContainerConfigurationArgs $;

        public Builder() {
            $ = new ContainerConfigurationArgs();
        }

        public Builder(ContainerConfigurationArgs defaults) {
            $ = new ContainerConfigurationArgs(Objects.requireNonNull(defaults));
        }

        public Builder compartmentId(Output<String> compartmentId) {
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
        public Builder isRepositoryCreatedOnFirstPush(Output<Boolean> isRepositoryCreatedOnFirstPush) {
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

        public ContainerConfigurationArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("ContainerConfigurationArgs", "compartmentId");
            }
            if ($.isRepositoryCreatedOnFirstPush == null) {
                throw new MissingRequiredPropertyException("ContainerConfigurationArgs", "isRepositoryCreatedOnFirstPush");
            }
            return $;
        }
    }

}
