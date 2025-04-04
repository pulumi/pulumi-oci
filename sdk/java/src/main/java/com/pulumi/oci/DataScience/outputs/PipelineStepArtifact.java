// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class PipelineStepArtifact {
    private @Nullable String artifactContentDisposition;
    private @Nullable String artifactContentLength;
    private @Nullable String artifactContentMd5;
    private @Nullable String artifactLastModified;
    private String pipelineStepArtifact;
    /**
     * @return The name of the step. It must be unique within the pipeline. This is used to create the pipeline DAG.
     * 
     */
    private String stepName;

    private PipelineStepArtifact() {}
    public Optional<String> artifactContentDisposition() {
        return Optional.ofNullable(this.artifactContentDisposition);
    }
    public Optional<String> artifactContentLength() {
        return Optional.ofNullable(this.artifactContentLength);
    }
    public Optional<String> artifactContentMd5() {
        return Optional.ofNullable(this.artifactContentMd5);
    }
    public Optional<String> artifactLastModified() {
        return Optional.ofNullable(this.artifactLastModified);
    }
    public String pipelineStepArtifact() {
        return this.pipelineStepArtifact;
    }
    /**
     * @return The name of the step. It must be unique within the pipeline. This is used to create the pipeline DAG.
     * 
     */
    public String stepName() {
        return this.stepName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(PipelineStepArtifact defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String artifactContentDisposition;
        private @Nullable String artifactContentLength;
        private @Nullable String artifactContentMd5;
        private @Nullable String artifactLastModified;
        private String pipelineStepArtifact;
        private String stepName;
        public Builder() {}
        public Builder(PipelineStepArtifact defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.artifactContentDisposition = defaults.artifactContentDisposition;
    	      this.artifactContentLength = defaults.artifactContentLength;
    	      this.artifactContentMd5 = defaults.artifactContentMd5;
    	      this.artifactLastModified = defaults.artifactLastModified;
    	      this.pipelineStepArtifact = defaults.pipelineStepArtifact;
    	      this.stepName = defaults.stepName;
        }

        @CustomType.Setter
        public Builder artifactContentDisposition(@Nullable String artifactContentDisposition) {

            this.artifactContentDisposition = artifactContentDisposition;
            return this;
        }
        @CustomType.Setter
        public Builder artifactContentLength(@Nullable String artifactContentLength) {

            this.artifactContentLength = artifactContentLength;
            return this;
        }
        @CustomType.Setter
        public Builder artifactContentMd5(@Nullable String artifactContentMd5) {

            this.artifactContentMd5 = artifactContentMd5;
            return this;
        }
        @CustomType.Setter
        public Builder artifactLastModified(@Nullable String artifactLastModified) {

            this.artifactLastModified = artifactLastModified;
            return this;
        }
        @CustomType.Setter
        public Builder pipelineStepArtifact(String pipelineStepArtifact) {
            if (pipelineStepArtifact == null) {
              throw new MissingRequiredPropertyException("PipelineStepArtifact", "pipelineStepArtifact");
            }
            this.pipelineStepArtifact = pipelineStepArtifact;
            return this;
        }
        @CustomType.Setter
        public Builder stepName(String stepName) {
            if (stepName == null) {
              throw new MissingRequiredPropertyException("PipelineStepArtifact", "stepName");
            }
            this.stepName = stepName;
            return this;
        }
        public PipelineStepArtifact build() {
            final var _resultValue = new PipelineStepArtifact();
            _resultValue.artifactContentDisposition = artifactContentDisposition;
            _resultValue.artifactContentLength = artifactContentLength;
            _resultValue.artifactContentMd5 = artifactContentMd5;
            _resultValue.artifactLastModified = artifactLastModified;
            _resultValue.pipelineStepArtifact = pipelineStepArtifact;
            _resultValue.stepName = stepName;
            return _resultValue;
        }
    }
}
