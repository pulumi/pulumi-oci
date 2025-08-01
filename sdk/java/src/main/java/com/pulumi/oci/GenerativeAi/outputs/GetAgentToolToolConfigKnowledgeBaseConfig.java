// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GenerativeAi.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetAgentToolToolConfigKnowledgeBaseConfig {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the knowledgeBase this RAG Tool uses
     * 
     */
    private String knowledgeBaseId;

    private GetAgentToolToolConfigKnowledgeBaseConfig() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the knowledgeBase this RAG Tool uses
     * 
     */
    public String knowledgeBaseId() {
        return this.knowledgeBaseId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAgentToolToolConfigKnowledgeBaseConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String knowledgeBaseId;
        public Builder() {}
        public Builder(GetAgentToolToolConfigKnowledgeBaseConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.knowledgeBaseId = defaults.knowledgeBaseId;
        }

        @CustomType.Setter
        public Builder knowledgeBaseId(String knowledgeBaseId) {
            if (knowledgeBaseId == null) {
              throw new MissingRequiredPropertyException("GetAgentToolToolConfigKnowledgeBaseConfig", "knowledgeBaseId");
            }
            this.knowledgeBaseId = knowledgeBaseId;
            return this;
        }
        public GetAgentToolToolConfigKnowledgeBaseConfig build() {
            final var _resultValue = new GetAgentToolToolConfigKnowledgeBaseConfig();
            _resultValue.knowledgeBaseId = knowledgeBaseId;
            return _resultValue;
        }
    }
}
