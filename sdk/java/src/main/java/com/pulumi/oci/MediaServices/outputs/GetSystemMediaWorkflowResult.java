// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MediaServices.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.MediaServices.outputs.GetSystemMediaWorkflowItem;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetSystemMediaWorkflowResult {
    private @Nullable String compartmentId;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return List of SytemMediaWorkflow items.
     * 
     */
    private List<GetSystemMediaWorkflowItem> items;
    /**
     * @return System provided unique identifier for this static media workflow.
     * 
     */
    private @Nullable String name;

    private GetSystemMediaWorkflowResult() {}
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return List of SytemMediaWorkflow items.
     * 
     */
    public List<GetSystemMediaWorkflowItem> items() {
        return this.items;
    }
    /**
     * @return System provided unique identifier for this static media workflow.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSystemMediaWorkflowResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String compartmentId;
        private String id;
        private List<GetSystemMediaWorkflowItem> items;
        private @Nullable String name;
        public Builder() {}
        public Builder(GetSystemMediaWorkflowResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.id = defaults.id;
    	      this.items = defaults.items;
    	      this.name = defaults.name;
        }

        @CustomType.Setter
        public Builder compartmentId(@Nullable String compartmentId) {

            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetSystemMediaWorkflowResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder items(List<GetSystemMediaWorkflowItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetSystemMediaWorkflowResult", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetSystemMediaWorkflowItem... items) {
            return items(List.of(items));
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {

            this.name = name;
            return this;
        }
        public GetSystemMediaWorkflowResult build() {
            final var _resultValue = new GetSystemMediaWorkflowResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.id = id;
            _resultValue.items = items;
            _resultValue.name = name;
            return _resultValue;
        }
    }
}
