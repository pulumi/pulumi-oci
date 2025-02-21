// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GenerativeAi.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetAgentDataIngestionJobLogContentResult {
    private String dataIngestionJobId;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;

    private GetAgentDataIngestionJobLogContentResult() {}
    public String dataIngestionJobId() {
        return this.dataIngestionJobId;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAgentDataIngestionJobLogContentResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String dataIngestionJobId;
        private String id;
        public Builder() {}
        public Builder(GetAgentDataIngestionJobLogContentResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.dataIngestionJobId = defaults.dataIngestionJobId;
    	      this.id = defaults.id;
        }

        @CustomType.Setter
        public Builder dataIngestionJobId(String dataIngestionJobId) {
            if (dataIngestionJobId == null) {
              throw new MissingRequiredPropertyException("GetAgentDataIngestionJobLogContentResult", "dataIngestionJobId");
            }
            this.dataIngestionJobId = dataIngestionJobId;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetAgentDataIngestionJobLogContentResult", "id");
            }
            this.id = id;
            return this;
        }
        public GetAgentDataIngestionJobLogContentResult build() {
            final var _resultValue = new GetAgentDataIngestionJobLogContentResult();
            _resultValue.dataIngestionJobId = dataIngestionJobId;
            _resultValue.id = id;
            return _resultValue;
        }
    }
}
