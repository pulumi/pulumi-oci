// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DevOps.outputs.GetRepoFileLineLine;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetRepoFileLineResult {
    private String filePath;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of lines in the file.
     * 
     */
    private List<GetRepoFileLineLine> lines;
    private String repositoryId;
    private String revision;
    private @Nullable Integer startLineNumber;

    private GetRepoFileLineResult() {}
    public String filePath() {
        return this.filePath;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The list of lines in the file.
     * 
     */
    public List<GetRepoFileLineLine> lines() {
        return this.lines;
    }
    public String repositoryId() {
        return this.repositoryId;
    }
    public String revision() {
        return this.revision;
    }
    public Optional<Integer> startLineNumber() {
        return Optional.ofNullable(this.startLineNumber);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRepoFileLineResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String filePath;
        private String id;
        private List<GetRepoFileLineLine> lines;
        private String repositoryId;
        private String revision;
        private @Nullable Integer startLineNumber;
        public Builder() {}
        public Builder(GetRepoFileLineResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filePath = defaults.filePath;
    	      this.id = defaults.id;
    	      this.lines = defaults.lines;
    	      this.repositoryId = defaults.repositoryId;
    	      this.revision = defaults.revision;
    	      this.startLineNumber = defaults.startLineNumber;
        }

        @CustomType.Setter
        public Builder filePath(String filePath) {
            this.filePath = Objects.requireNonNull(filePath);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder lines(List<GetRepoFileLineLine> lines) {
            this.lines = Objects.requireNonNull(lines);
            return this;
        }
        public Builder lines(GetRepoFileLineLine... lines) {
            return lines(List.of(lines));
        }
        @CustomType.Setter
        public Builder repositoryId(String repositoryId) {
            this.repositoryId = Objects.requireNonNull(repositoryId);
            return this;
        }
        @CustomType.Setter
        public Builder revision(String revision) {
            this.revision = Objects.requireNonNull(revision);
            return this;
        }
        @CustomType.Setter
        public Builder startLineNumber(@Nullable Integer startLineNumber) {
            this.startLineNumber = startLineNumber;
            return this;
        }
        public GetRepoFileLineResult build() {
            final var o = new GetRepoFileLineResult();
            o.filePath = filePath;
            o.id = id;
            o.lines = lines;
            o.repositoryId = repositoryId;
            o.revision = revision;
            o.startLineNumber = startLineNumber;
            return o;
        }
    }
}