// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.CloudGuard.outputs.GetProblemEntityItem;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetProblemEntityResult {
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return List of problem entities summaries related to a data source.
     * 
     */
    private List<GetProblemEntityItem> items;
    /**
     * @return Attached problem id
     * 
     */
    private String problemId;

    private GetProblemEntityResult() {}
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return List of problem entities summaries related to a data source.
     * 
     */
    public List<GetProblemEntityItem> items() {
        return this.items;
    }
    /**
     * @return Attached problem id
     * 
     */
    public String problemId() {
        return this.problemId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetProblemEntityResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String id;
        private List<GetProblemEntityItem> items;
        private String problemId;
        public Builder() {}
        public Builder(GetProblemEntityResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.id = defaults.id;
    	      this.items = defaults.items;
    	      this.problemId = defaults.problemId;
        }

        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetProblemEntityResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder items(List<GetProblemEntityItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetProblemEntityResult", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetProblemEntityItem... items) {
            return items(List.of(items));
        }
        @CustomType.Setter
        public Builder problemId(String problemId) {
            if (problemId == null) {
              throw new MissingRequiredPropertyException("GetProblemEntityResult", "problemId");
            }
            this.problemId = problemId;
            return this;
        }
        public GetProblemEntityResult build() {
            final var _resultValue = new GetProblemEntityResult();
            _resultValue.id = id;
            _resultValue.items = items;
            _resultValue.problemId = problemId;
            return _resultValue;
        }
    }
}
