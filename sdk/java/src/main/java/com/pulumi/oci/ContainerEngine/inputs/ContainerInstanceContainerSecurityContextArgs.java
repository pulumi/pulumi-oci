// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.ContainerEngine.inputs.ContainerInstanceContainerSecurityContextCapabilitiesArgs;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ContainerInstanceContainerSecurityContextArgs extends com.pulumi.resources.ResourceArgs {

    public static final ContainerInstanceContainerSecurityContextArgs Empty = new ContainerInstanceContainerSecurityContextArgs();

    /**
     * Linux Container capabilities to configure capabilities of container.
     * 
     */
    @Import(name="capabilities")
    private @Nullable Output<ContainerInstanceContainerSecurityContextCapabilitiesArgs> capabilities;

    /**
     * @return Linux Container capabilities to configure capabilities of container.
     * 
     */
    public Optional<Output<ContainerInstanceContainerSecurityContextCapabilitiesArgs>> capabilities() {
        return Optional.ofNullable(this.capabilities);
    }

    /**
     * Indicates if the container must run as a non-root user. If true, the service validates the container image at runtime to ensure that it is not going to run with UID 0 (root) and fails the container instance creation if the validation fails.
     * 
     */
    @Import(name="isNonRootUserCheckEnabled")
    private @Nullable Output<Boolean> isNonRootUserCheckEnabled;

    /**
     * @return Indicates if the container must run as a non-root user. If true, the service validates the container image at runtime to ensure that it is not going to run with UID 0 (root) and fails the container instance creation if the validation fails.
     * 
     */
    public Optional<Output<Boolean>> isNonRootUserCheckEnabled() {
        return Optional.ofNullable(this.isNonRootUserCheckEnabled);
    }

    /**
     * Determines if the container will have a read-only root file system. Default value is false.
     * 
     */
    @Import(name="isRootFileSystemReadonly")
    private @Nullable Output<Boolean> isRootFileSystemReadonly;

    /**
     * @return Determines if the container will have a read-only root file system. Default value is false.
     * 
     */
    public Optional<Output<Boolean>> isRootFileSystemReadonly() {
        return Optional.ofNullable(this.isRootFileSystemReadonly);
    }

    /**
     * The group ID (GID) to run the entrypoint process of the container. Uses runtime default if not provided.
     * 
     */
    @Import(name="runAsGroup")
    private @Nullable Output<Integer> runAsGroup;

    /**
     * @return The group ID (GID) to run the entrypoint process of the container. Uses runtime default if not provided.
     * 
     */
    public Optional<Output<Integer>> runAsGroup() {
        return Optional.ofNullable(this.runAsGroup);
    }

    /**
     * The user ID (UID) to run the entrypoint process of the container. Defaults to user specified UID in container image metadata if not provided. This must be provided if runAsGroup is provided.
     * 
     */
    @Import(name="runAsUser")
    private @Nullable Output<Integer> runAsUser;

    /**
     * @return The user ID (UID) to run the entrypoint process of the container. Defaults to user specified UID in container image metadata if not provided. This must be provided if runAsGroup is provided.
     * 
     */
    public Optional<Output<Integer>> runAsUser() {
        return Optional.ofNullable(this.runAsUser);
    }

    /**
     * The type of security context
     * 
     */
    @Import(name="securityContextType")
    private @Nullable Output<String> securityContextType;

    /**
     * @return The type of security context
     * 
     */
    public Optional<Output<String>> securityContextType() {
        return Optional.ofNullable(this.securityContextType);
    }

    private ContainerInstanceContainerSecurityContextArgs() {}

    private ContainerInstanceContainerSecurityContextArgs(ContainerInstanceContainerSecurityContextArgs $) {
        this.capabilities = $.capabilities;
        this.isNonRootUserCheckEnabled = $.isNonRootUserCheckEnabled;
        this.isRootFileSystemReadonly = $.isRootFileSystemReadonly;
        this.runAsGroup = $.runAsGroup;
        this.runAsUser = $.runAsUser;
        this.securityContextType = $.securityContextType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ContainerInstanceContainerSecurityContextArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ContainerInstanceContainerSecurityContextArgs $;

        public Builder() {
            $ = new ContainerInstanceContainerSecurityContextArgs();
        }

        public Builder(ContainerInstanceContainerSecurityContextArgs defaults) {
            $ = new ContainerInstanceContainerSecurityContextArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param capabilities Linux Container capabilities to configure capabilities of container.
         * 
         * @return builder
         * 
         */
        public Builder capabilities(@Nullable Output<ContainerInstanceContainerSecurityContextCapabilitiesArgs> capabilities) {
            $.capabilities = capabilities;
            return this;
        }

        /**
         * @param capabilities Linux Container capabilities to configure capabilities of container.
         * 
         * @return builder
         * 
         */
        public Builder capabilities(ContainerInstanceContainerSecurityContextCapabilitiesArgs capabilities) {
            return capabilities(Output.of(capabilities));
        }

        /**
         * @param isNonRootUserCheckEnabled Indicates if the container must run as a non-root user. If true, the service validates the container image at runtime to ensure that it is not going to run with UID 0 (root) and fails the container instance creation if the validation fails.
         * 
         * @return builder
         * 
         */
        public Builder isNonRootUserCheckEnabled(@Nullable Output<Boolean> isNonRootUserCheckEnabled) {
            $.isNonRootUserCheckEnabled = isNonRootUserCheckEnabled;
            return this;
        }

        /**
         * @param isNonRootUserCheckEnabled Indicates if the container must run as a non-root user. If true, the service validates the container image at runtime to ensure that it is not going to run with UID 0 (root) and fails the container instance creation if the validation fails.
         * 
         * @return builder
         * 
         */
        public Builder isNonRootUserCheckEnabled(Boolean isNonRootUserCheckEnabled) {
            return isNonRootUserCheckEnabled(Output.of(isNonRootUserCheckEnabled));
        }

        /**
         * @param isRootFileSystemReadonly Determines if the container will have a read-only root file system. Default value is false.
         * 
         * @return builder
         * 
         */
        public Builder isRootFileSystemReadonly(@Nullable Output<Boolean> isRootFileSystemReadonly) {
            $.isRootFileSystemReadonly = isRootFileSystemReadonly;
            return this;
        }

        /**
         * @param isRootFileSystemReadonly Determines if the container will have a read-only root file system. Default value is false.
         * 
         * @return builder
         * 
         */
        public Builder isRootFileSystemReadonly(Boolean isRootFileSystemReadonly) {
            return isRootFileSystemReadonly(Output.of(isRootFileSystemReadonly));
        }

        /**
         * @param runAsGroup The group ID (GID) to run the entrypoint process of the container. Uses runtime default if not provided.
         * 
         * @return builder
         * 
         */
        public Builder runAsGroup(@Nullable Output<Integer> runAsGroup) {
            $.runAsGroup = runAsGroup;
            return this;
        }

        /**
         * @param runAsGroup The group ID (GID) to run the entrypoint process of the container. Uses runtime default if not provided.
         * 
         * @return builder
         * 
         */
        public Builder runAsGroup(Integer runAsGroup) {
            return runAsGroup(Output.of(runAsGroup));
        }

        /**
         * @param runAsUser The user ID (UID) to run the entrypoint process of the container. Defaults to user specified UID in container image metadata if not provided. This must be provided if runAsGroup is provided.
         * 
         * @return builder
         * 
         */
        public Builder runAsUser(@Nullable Output<Integer> runAsUser) {
            $.runAsUser = runAsUser;
            return this;
        }

        /**
         * @param runAsUser The user ID (UID) to run the entrypoint process of the container. Defaults to user specified UID in container image metadata if not provided. This must be provided if runAsGroup is provided.
         * 
         * @return builder
         * 
         */
        public Builder runAsUser(Integer runAsUser) {
            return runAsUser(Output.of(runAsUser));
        }

        /**
         * @param securityContextType The type of security context
         * 
         * @return builder
         * 
         */
        public Builder securityContextType(@Nullable Output<String> securityContextType) {
            $.securityContextType = securityContextType;
            return this;
        }

        /**
         * @param securityContextType The type of security context
         * 
         * @return builder
         * 
         */
        public Builder securityContextType(String securityContextType) {
            return securityContextType(Output.of(securityContextType));
        }

        public ContainerInstanceContainerSecurityContextArgs build() {
            return $;
        }
    }

}
