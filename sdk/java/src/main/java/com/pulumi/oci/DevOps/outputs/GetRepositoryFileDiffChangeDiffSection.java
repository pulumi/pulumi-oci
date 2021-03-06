// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DevOps.outputs.GetRepositoryFileDiffChangeDiffSectionLine;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetRepositoryFileDiffChangeDiffSection {
    /**
     * @return The lines within changed section.
     * 
     */
    private final List<GetRepositoryFileDiffChangeDiffSectionLine> lines;
    /**
     * @return Type of change.
     * 
     */
    private final String type;

    @CustomType.Constructor
    private GetRepositoryFileDiffChangeDiffSection(
        @CustomType.Parameter("lines") List<GetRepositoryFileDiffChangeDiffSectionLine> lines,
        @CustomType.Parameter("type") String type) {
        this.lines = lines;
        this.type = type;
    }

    /**
     * @return The lines within changed section.
     * 
     */
    public List<GetRepositoryFileDiffChangeDiffSectionLine> lines() {
        return this.lines;
    }
    /**
     * @return Type of change.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRepositoryFileDiffChangeDiffSection defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetRepositoryFileDiffChangeDiffSectionLine> lines;
        private String type;

        public Builder() {
    	      // Empty
        }

        public Builder(GetRepositoryFileDiffChangeDiffSection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.lines = defaults.lines;
    	      this.type = defaults.type;
        }

        public Builder lines(List<GetRepositoryFileDiffChangeDiffSectionLine> lines) {
            this.lines = Objects.requireNonNull(lines);
            return this;
        }
        public Builder lines(GetRepositoryFileDiffChangeDiffSectionLine... lines) {
            return lines(List.of(lines));
        }
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }        public GetRepositoryFileDiffChangeDiffSection build() {
            return new GetRepositoryFileDiffChangeDiffSection(lines, type);
        }
    }
}
