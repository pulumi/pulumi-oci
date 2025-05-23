// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GenerativeAi.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetAgentKnowledgeBaseIndexConfigDatabaseFunction {
    /**
     * @return The index name in opensearch.
     * 
     */
    private String name;

    private GetAgentKnowledgeBaseIndexConfigDatabaseFunction() {}
    /**
     * @return The index name in opensearch.
     * 
     */
    public String name() {
        return this.name;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAgentKnowledgeBaseIndexConfigDatabaseFunction defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String name;
        public Builder() {}
        public Builder(GetAgentKnowledgeBaseIndexConfigDatabaseFunction defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
        }

        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetAgentKnowledgeBaseIndexConfigDatabaseFunction", "name");
            }
            this.name = name;
            return this;
        }
        public GetAgentKnowledgeBaseIndexConfigDatabaseFunction build() {
            final var _resultValue = new GetAgentKnowledgeBaseIndexConfigDatabaseFunction();
            _resultValue.name = name;
            return _resultValue;
        }
    }
}
