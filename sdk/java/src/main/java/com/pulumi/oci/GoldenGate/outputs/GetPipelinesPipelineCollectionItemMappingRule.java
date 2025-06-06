// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GoldenGate.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetPipelinesPipelineCollectionItemMappingRule {
    /**
     * @return Defines the exclude/include rules of source and target schemas and tables when replicating from source to target. This option applies when creating and updating a pipeline.
     * 
     */
    private String mappingType;
    /**
     * @return The source schema/table combination for replication to target.
     * 
     */
    private String source;
    /**
     * @return The target schema/table combination for replication from the source.
     * 
     */
    private String target;

    private GetPipelinesPipelineCollectionItemMappingRule() {}
    /**
     * @return Defines the exclude/include rules of source and target schemas and tables when replicating from source to target. This option applies when creating and updating a pipeline.
     * 
     */
    public String mappingType() {
        return this.mappingType;
    }
    /**
     * @return The source schema/table combination for replication to target.
     * 
     */
    public String source() {
        return this.source;
    }
    /**
     * @return The target schema/table combination for replication from the source.
     * 
     */
    public String target() {
        return this.target;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPipelinesPipelineCollectionItemMappingRule defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String mappingType;
        private String source;
        private String target;
        public Builder() {}
        public Builder(GetPipelinesPipelineCollectionItemMappingRule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.mappingType = defaults.mappingType;
    	      this.source = defaults.source;
    	      this.target = defaults.target;
        }

        @CustomType.Setter
        public Builder mappingType(String mappingType) {
            if (mappingType == null) {
              throw new MissingRequiredPropertyException("GetPipelinesPipelineCollectionItemMappingRule", "mappingType");
            }
            this.mappingType = mappingType;
            return this;
        }
        @CustomType.Setter
        public Builder source(String source) {
            if (source == null) {
              throw new MissingRequiredPropertyException("GetPipelinesPipelineCollectionItemMappingRule", "source");
            }
            this.source = source;
            return this;
        }
        @CustomType.Setter
        public Builder target(String target) {
            if (target == null) {
              throw new MissingRequiredPropertyException("GetPipelinesPipelineCollectionItemMappingRule", "target");
            }
            this.target = target;
            return this;
        }
        public GetPipelinesPipelineCollectionItemMappingRule build() {
            final var _resultValue = new GetPipelinesPipelineCollectionItemMappingRule();
            _resultValue.mappingType = mappingType;
            _resultValue.source = source;
            _resultValue.target = target;
            return _resultValue;
        }
    }
}
