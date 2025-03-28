// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetRepoFileLinePlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetRepoFileLinePlainArgs Empty = new GetRepoFileLinePlainArgs();

    /**
     * (Required) A filter to return file contents of the specified paths.
     * 
     */
    @Import(name="filePath", required=true)
    private String filePath;

    /**
     * @return (Required) A filter to return file contents of the specified paths.
     * 
     */
    public String filePath() {
        return this.filePath;
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

    /**
     * Retrieve file lines from specific revision.
     * 
     */
    @Import(name="revision", required=true)
    private String revision;

    /**
     * @return Retrieve file lines from specific revision.
     * 
     */
    public String revision() {
        return this.revision;
    }

    /**
     * Line number from where to start returning file lines.
     * 
     */
    @Import(name="startLineNumber")
    private @Nullable Integer startLineNumber;

    /**
     * @return Line number from where to start returning file lines.
     * 
     */
    public Optional<Integer> startLineNumber() {
        return Optional.ofNullable(this.startLineNumber);
    }

    private GetRepoFileLinePlainArgs() {}

    private GetRepoFileLinePlainArgs(GetRepoFileLinePlainArgs $) {
        this.filePath = $.filePath;
        this.repositoryId = $.repositoryId;
        this.revision = $.revision;
        this.startLineNumber = $.startLineNumber;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetRepoFileLinePlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetRepoFileLinePlainArgs $;

        public Builder() {
            $ = new GetRepoFileLinePlainArgs();
        }

        public Builder(GetRepoFileLinePlainArgs defaults) {
            $ = new GetRepoFileLinePlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param filePath (Required) A filter to return file contents of the specified paths.
         * 
         * @return builder
         * 
         */
        public Builder filePath(String filePath) {
            $.filePath = filePath;
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

        /**
         * @param revision Retrieve file lines from specific revision.
         * 
         * @return builder
         * 
         */
        public Builder revision(String revision) {
            $.revision = revision;
            return this;
        }

        /**
         * @param startLineNumber Line number from where to start returning file lines.
         * 
         * @return builder
         * 
         */
        public Builder startLineNumber(@Nullable Integer startLineNumber) {
            $.startLineNumber = startLineNumber;
            return this;
        }

        public GetRepoFileLinePlainArgs build() {
            if ($.filePath == null) {
                throw new MissingRequiredPropertyException("GetRepoFileLinePlainArgs", "filePath");
            }
            if ($.repositoryId == null) {
                throw new MissingRequiredPropertyException("GetRepoFileLinePlainArgs", "repositoryId");
            }
            if ($.revision == null) {
                throw new MissingRequiredPropertyException("GetRepoFileLinePlainArgs", "revision");
            }
            return $;
        }
    }

}
