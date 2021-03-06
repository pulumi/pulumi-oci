// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DevOps.outputs.GetBuildRunBuildOutputExportedVariableItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetBuildRunBuildOutputExportedVariable {
    /**
     * @return List of exported variables.
     * 
     */
    private final List<GetBuildRunBuildOutputExportedVariableItem> items;

    @CustomType.Constructor
    private GetBuildRunBuildOutputExportedVariable(@CustomType.Parameter("items") List<GetBuildRunBuildOutputExportedVariableItem> items) {
        this.items = items;
    }

    /**
     * @return List of exported variables.
     * 
     */
    public List<GetBuildRunBuildOutputExportedVariableItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBuildRunBuildOutputExportedVariable defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetBuildRunBuildOutputExportedVariableItem> items;

        public Builder() {
    	      // Empty
        }

        public Builder(GetBuildRunBuildOutputExportedVariable defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        public Builder items(List<GetBuildRunBuildOutputExportedVariableItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetBuildRunBuildOutputExportedVariableItem... items) {
            return items(List.of(items));
        }        public GetBuildRunBuildOutputExportedVariable build() {
            return new GetBuildRunBuildOutputExportedVariable(items);
        }
    }
}
