// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DevOps.outputs.GetBuildRunBuildOutputDeliveredArtifactItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetBuildRunBuildOutputDeliveredArtifact {
    /**
     * @return List of exported variables.
     * 
     */
    private final List<GetBuildRunBuildOutputDeliveredArtifactItem> items;

    @CustomType.Constructor
    private GetBuildRunBuildOutputDeliveredArtifact(@CustomType.Parameter("items") List<GetBuildRunBuildOutputDeliveredArtifactItem> items) {
        this.items = items;
    }

    /**
     * @return List of exported variables.
     * 
     */
    public List<GetBuildRunBuildOutputDeliveredArtifactItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBuildRunBuildOutputDeliveredArtifact defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetBuildRunBuildOutputDeliveredArtifactItem> items;

        public Builder() {
    	      // Empty
        }

        public Builder(GetBuildRunBuildOutputDeliveredArtifact defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        public Builder items(List<GetBuildRunBuildOutputDeliveredArtifactItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetBuildRunBuildOutputDeliveredArtifactItem... items) {
            return items(List.of(items));
        }        public GetBuildRunBuildOutputDeliveredArtifact build() {
            return new GetBuildRunBuildOutputDeliveredArtifact(items);
        }
    }
}
