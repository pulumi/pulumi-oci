// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class ModelArtifactExportArgs extends com.pulumi.resources.ResourceArgs {

    public static final ModelArtifactExportArgs Empty = new ModelArtifactExportArgs();

    @Import(name="artifactSourceType", required=true)
    private Output<String> artifactSourceType;

    public Output<String> artifactSourceType() {
        return this.artifactSourceType;
    }

    @Import(name="modelId", required=true)
    private Output<String> modelId;

    public Output<String> modelId() {
        return this.modelId;
    }

    @Import(name="namespace", required=true)
    private Output<String> namespace;

    public Output<String> namespace() {
        return this.namespace;
    }

    @Import(name="sourceBucket", required=true)
    private Output<String> sourceBucket;

    public Output<String> sourceBucket() {
        return this.sourceBucket;
    }

    @Import(name="sourceObjectName", required=true)
    private Output<String> sourceObjectName;

    public Output<String> sourceObjectName() {
        return this.sourceObjectName;
    }

    @Import(name="sourceRegion", required=true)
    private Output<String> sourceRegion;

    public Output<String> sourceRegion() {
        return this.sourceRegion;
    }

    private ModelArtifactExportArgs() {}

    private ModelArtifactExportArgs(ModelArtifactExportArgs $) {
        this.artifactSourceType = $.artifactSourceType;
        this.modelId = $.modelId;
        this.namespace = $.namespace;
        this.sourceBucket = $.sourceBucket;
        this.sourceObjectName = $.sourceObjectName;
        this.sourceRegion = $.sourceRegion;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ModelArtifactExportArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ModelArtifactExportArgs $;

        public Builder() {
            $ = new ModelArtifactExportArgs();
        }

        public Builder(ModelArtifactExportArgs defaults) {
            $ = new ModelArtifactExportArgs(Objects.requireNonNull(defaults));
        }

        public Builder artifactSourceType(Output<String> artifactSourceType) {
            $.artifactSourceType = artifactSourceType;
            return this;
        }

        public Builder artifactSourceType(String artifactSourceType) {
            return artifactSourceType(Output.of(artifactSourceType));
        }

        public Builder modelId(Output<String> modelId) {
            $.modelId = modelId;
            return this;
        }

        public Builder modelId(String modelId) {
            return modelId(Output.of(modelId));
        }

        public Builder namespace(Output<String> namespace) {
            $.namespace = namespace;
            return this;
        }

        public Builder namespace(String namespace) {
            return namespace(Output.of(namespace));
        }

        public Builder sourceBucket(Output<String> sourceBucket) {
            $.sourceBucket = sourceBucket;
            return this;
        }

        public Builder sourceBucket(String sourceBucket) {
            return sourceBucket(Output.of(sourceBucket));
        }

        public Builder sourceObjectName(Output<String> sourceObjectName) {
            $.sourceObjectName = sourceObjectName;
            return this;
        }

        public Builder sourceObjectName(String sourceObjectName) {
            return sourceObjectName(Output.of(sourceObjectName));
        }

        public Builder sourceRegion(Output<String> sourceRegion) {
            $.sourceRegion = sourceRegion;
            return this;
        }

        public Builder sourceRegion(String sourceRegion) {
            return sourceRegion(Output.of(sourceRegion));
        }

        public ModelArtifactExportArgs build() {
            if ($.artifactSourceType == null) {
                throw new MissingRequiredPropertyException("ModelArtifactExportArgs", "artifactSourceType");
            }
            if ($.modelId == null) {
                throw new MissingRequiredPropertyException("ModelArtifactExportArgs", "modelId");
            }
            if ($.namespace == null) {
                throw new MissingRequiredPropertyException("ModelArtifactExportArgs", "namespace");
            }
            if ($.sourceBucket == null) {
                throw new MissingRequiredPropertyException("ModelArtifactExportArgs", "sourceBucket");
            }
            if ($.sourceObjectName == null) {
                throw new MissingRequiredPropertyException("ModelArtifactExportArgs", "sourceObjectName");
            }
            if ($.sourceRegion == null) {
                throw new MissingRequiredPropertyException("ModelArtifactExportArgs", "sourceRegion");
            }
            return $;
        }
    }

}
