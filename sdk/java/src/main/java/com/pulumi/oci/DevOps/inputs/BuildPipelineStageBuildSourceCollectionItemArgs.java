// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class BuildPipelineStageBuildSourceCollectionItemArgs extends com.pulumi.resources.ResourceArgs {

    public static final BuildPipelineStageBuildSourceCollectionItemArgs Empty = new BuildPipelineStageBuildSourceCollectionItemArgs();

    /**
     * (Updatable) Branch name.
     * 
     */
    @Import(name="branch")
    private @Nullable Output<String> branch;

    /**
     * @return (Updatable) Branch name.
     * 
     */
    public Optional<Output<String>> branch() {
        return Optional.ofNullable(this.branch);
    }

    /**
     * (Updatable) Connection identifier pertinent to Bitbucket Server source provider
     * 
     */
    @Import(name="connectionId")
    private @Nullable Output<String> connectionId;

    /**
     * @return (Updatable) Connection identifier pertinent to Bitbucket Server source provider
     * 
     */
    public Optional<Output<String>> connectionId() {
        return Optional.ofNullable(this.connectionId);
    }

    /**
     * (Updatable) The type of source provider.
     * 
     */
    @Import(name="connectionType", required=true)
    private Output<String> connectionType;

    /**
     * @return (Updatable) The type of source provider.
     * 
     */
    public Output<String> connectionType() {
        return this.connectionType;
    }

    /**
     * (Updatable) Name of the build source. This must be unique within a build source collection. The name can be used by customers to locate the working directory pertinent to this repository.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return (Updatable) Name of the build source. This must be unique within a build source collection. The name can be used by customers to locate the working directory pertinent to this repository.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * (Updatable) The DevOps code repository ID.
     * 
     */
    @Import(name="repositoryId")
    private @Nullable Output<String> repositoryId;

    /**
     * @return (Updatable) The DevOps code repository ID.
     * 
     */
    public Optional<Output<String>> repositoryId() {
        return Optional.ofNullable(this.repositoryId);
    }

    /**
     * (Updatable) URL for the repository.
     * 
     */
    @Import(name="repositoryUrl")
    private @Nullable Output<String> repositoryUrl;

    /**
     * @return (Updatable) URL for the repository.
     * 
     */
    public Optional<Output<String>> repositoryUrl() {
        return Optional.ofNullable(this.repositoryUrl);
    }

    private BuildPipelineStageBuildSourceCollectionItemArgs() {}

    private BuildPipelineStageBuildSourceCollectionItemArgs(BuildPipelineStageBuildSourceCollectionItemArgs $) {
        this.branch = $.branch;
        this.connectionId = $.connectionId;
        this.connectionType = $.connectionType;
        this.name = $.name;
        this.repositoryId = $.repositoryId;
        this.repositoryUrl = $.repositoryUrl;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(BuildPipelineStageBuildSourceCollectionItemArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private BuildPipelineStageBuildSourceCollectionItemArgs $;

        public Builder() {
            $ = new BuildPipelineStageBuildSourceCollectionItemArgs();
        }

        public Builder(BuildPipelineStageBuildSourceCollectionItemArgs defaults) {
            $ = new BuildPipelineStageBuildSourceCollectionItemArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param branch (Updatable) Branch name.
         * 
         * @return builder
         * 
         */
        public Builder branch(@Nullable Output<String> branch) {
            $.branch = branch;
            return this;
        }

        /**
         * @param branch (Updatable) Branch name.
         * 
         * @return builder
         * 
         */
        public Builder branch(String branch) {
            return branch(Output.of(branch));
        }

        /**
         * @param connectionId (Updatable) Connection identifier pertinent to Bitbucket Server source provider
         * 
         * @return builder
         * 
         */
        public Builder connectionId(@Nullable Output<String> connectionId) {
            $.connectionId = connectionId;
            return this;
        }

        /**
         * @param connectionId (Updatable) Connection identifier pertinent to Bitbucket Server source provider
         * 
         * @return builder
         * 
         */
        public Builder connectionId(String connectionId) {
            return connectionId(Output.of(connectionId));
        }

        /**
         * @param connectionType (Updatable) The type of source provider.
         * 
         * @return builder
         * 
         */
        public Builder connectionType(Output<String> connectionType) {
            $.connectionType = connectionType;
            return this;
        }

        /**
         * @param connectionType (Updatable) The type of source provider.
         * 
         * @return builder
         * 
         */
        public Builder connectionType(String connectionType) {
            return connectionType(Output.of(connectionType));
        }

        /**
         * @param name (Updatable) Name of the build source. This must be unique within a build source collection. The name can be used by customers to locate the working directory pertinent to this repository.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) Name of the build source. This must be unique within a build source collection. The name can be used by customers to locate the working directory pertinent to this repository.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param repositoryId (Updatable) The DevOps code repository ID.
         * 
         * @return builder
         * 
         */
        public Builder repositoryId(@Nullable Output<String> repositoryId) {
            $.repositoryId = repositoryId;
            return this;
        }

        /**
         * @param repositoryId (Updatable) The DevOps code repository ID.
         * 
         * @return builder
         * 
         */
        public Builder repositoryId(String repositoryId) {
            return repositoryId(Output.of(repositoryId));
        }

        /**
         * @param repositoryUrl (Updatable) URL for the repository.
         * 
         * @return builder
         * 
         */
        public Builder repositoryUrl(@Nullable Output<String> repositoryUrl) {
            $.repositoryUrl = repositoryUrl;
            return this;
        }

        /**
         * @param repositoryUrl (Updatable) URL for the repository.
         * 
         * @return builder
         * 
         */
        public Builder repositoryUrl(String repositoryUrl) {
            return repositoryUrl(Output.of(repositoryUrl));
        }

        public BuildPipelineStageBuildSourceCollectionItemArgs build() {
            $.connectionType = Objects.requireNonNull($.connectionType, "expected parameter 'connectionType' to be non-null");
            return $;
        }
    }

}