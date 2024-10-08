// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetRepositoryObjectPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetRepositoryObjectPlainArgs Empty = new GetRepositoryObjectPlainArgs();

    /**
     * A filter to return only commits that affect any of the specified paths.
     * 
     */
    @Import(name="filePath")
    private @Nullable String filePath;

    /**
     * @return A filter to return only commits that affect any of the specified paths.
     * 
     */
    public Optional<String> filePath() {
        return Optional.ofNullable(this.filePath);
    }

    /**
     * A filter to return only resources that match the given reference name.
     * 
     */
    @Import(name="refName")
    private @Nullable String refName;

    /**
     * @return A filter to return only resources that match the given reference name.
     * 
     */
    public Optional<String> refName() {
        return Optional.ofNullable(this.refName);
    }

    /**
     * Unique repository identifier.
     * 
     */
    @Import(name="repositoryId", required=true)
    private String repositoryId;

    /**
     * @return Unique repository identifier.
     * 
     */
    public String repositoryId() {
        return this.repositoryId;
    }

    private GetRepositoryObjectPlainArgs() {}

    private GetRepositoryObjectPlainArgs(GetRepositoryObjectPlainArgs $) {
        this.filePath = $.filePath;
        this.refName = $.refName;
        this.repositoryId = $.repositoryId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetRepositoryObjectPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetRepositoryObjectPlainArgs $;

        public Builder() {
            $ = new GetRepositoryObjectPlainArgs();
        }

        public Builder(GetRepositoryObjectPlainArgs defaults) {
            $ = new GetRepositoryObjectPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param filePath A filter to return only commits that affect any of the specified paths.
         * 
         * @return builder
         * 
         */
        public Builder filePath(@Nullable String filePath) {
            $.filePath = filePath;
            return this;
        }

        /**
         * @param refName A filter to return only resources that match the given reference name.
         * 
         * @return builder
         * 
         */
        public Builder refName(@Nullable String refName) {
            $.refName = refName;
            return this;
        }

        /**
         * @param repositoryId Unique repository identifier.
         * 
         * @return builder
         * 
         */
        public Builder repositoryId(String repositoryId) {
            $.repositoryId = repositoryId;
            return this;
        }

        public GetRepositoryObjectPlainArgs build() {
            if ($.repositoryId == null) {
                throw new MissingRequiredPropertyException("GetRepositoryObjectPlainArgs", "repositoryId");
            }
            return $;
        }
    }

}
