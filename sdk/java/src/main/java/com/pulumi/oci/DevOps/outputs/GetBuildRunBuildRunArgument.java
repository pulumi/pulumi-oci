// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DevOps.outputs.GetBuildRunBuildRunArgumentItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetBuildRunBuildRunArgument {
    /**
     * @return List of exported variables.
     * 
     */
    private List<GetBuildRunBuildRunArgumentItem> items;

    private GetBuildRunBuildRunArgument() {}
    /**
     * @return List of exported variables.
     * 
     */
    public List<GetBuildRunBuildRunArgumentItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBuildRunBuildRunArgument defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetBuildRunBuildRunArgumentItem> items;
        public Builder() {}
        public Builder(GetBuildRunBuildRunArgument defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetBuildRunBuildRunArgumentItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetBuildRunBuildRunArgumentItem... items) {
            return items(List.of(items));
        }
        public GetBuildRunBuildRunArgument build() {
            final var o = new GetBuildRunBuildRunArgument();
            o.items = items;
            return o;
        }
    }
}