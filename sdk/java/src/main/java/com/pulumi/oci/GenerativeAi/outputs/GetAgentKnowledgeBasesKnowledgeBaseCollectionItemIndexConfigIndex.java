// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GenerativeAi.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.GenerativeAi.outputs.GetAgentKnowledgeBasesKnowledgeBaseCollectionItemIndexConfigIndexSchema;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetAgentKnowledgeBasesKnowledgeBaseCollectionItemIndexConfigIndex {
    /**
     * @return The index name in opensearch.
     * 
     */
    private String name;
    /**
     * @return **IndexSchema**
     * 
     */
    private List<GetAgentKnowledgeBasesKnowledgeBaseCollectionItemIndexConfigIndexSchema> schemas;

    private GetAgentKnowledgeBasesKnowledgeBaseCollectionItemIndexConfigIndex() {}
    /**
     * @return The index name in opensearch.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return **IndexSchema**
     * 
     */
    public List<GetAgentKnowledgeBasesKnowledgeBaseCollectionItemIndexConfigIndexSchema> schemas() {
        return this.schemas;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAgentKnowledgeBasesKnowledgeBaseCollectionItemIndexConfigIndex defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String name;
        private List<GetAgentKnowledgeBasesKnowledgeBaseCollectionItemIndexConfigIndexSchema> schemas;
        public Builder() {}
        public Builder(GetAgentKnowledgeBasesKnowledgeBaseCollectionItemIndexConfigIndex defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
    	      this.schemas = defaults.schemas;
        }

        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetAgentKnowledgeBasesKnowledgeBaseCollectionItemIndexConfigIndex", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder schemas(List<GetAgentKnowledgeBasesKnowledgeBaseCollectionItemIndexConfigIndexSchema> schemas) {
            if (schemas == null) {
              throw new MissingRequiredPropertyException("GetAgentKnowledgeBasesKnowledgeBaseCollectionItemIndexConfigIndex", "schemas");
            }
            this.schemas = schemas;
            return this;
        }
        public Builder schemas(GetAgentKnowledgeBasesKnowledgeBaseCollectionItemIndexConfigIndexSchema... schemas) {
            return schemas(List.of(schemas));
        }
        public GetAgentKnowledgeBasesKnowledgeBaseCollectionItemIndexConfigIndex build() {
            final var _resultValue = new GetAgentKnowledgeBasesKnowledgeBaseCollectionItemIndexConfigIndex();
            _resultValue.name = name;
            _resultValue.schemas = schemas;
            return _resultValue;
        }
    }
}
