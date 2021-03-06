// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Blockchain.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Blockchain.outputs.GetBlockchainPlatformsBlockchainPlatformCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetBlockchainPlatformsBlockchainPlatformCollection {
    private final List<GetBlockchainPlatformsBlockchainPlatformCollectionItem> items;

    @CustomType.Constructor
    private GetBlockchainPlatformsBlockchainPlatformCollection(@CustomType.Parameter("items") List<GetBlockchainPlatformsBlockchainPlatformCollectionItem> items) {
        this.items = items;
    }

    public List<GetBlockchainPlatformsBlockchainPlatformCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBlockchainPlatformsBlockchainPlatformCollection defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetBlockchainPlatformsBlockchainPlatformCollectionItem> items;

        public Builder() {
    	      // Empty
        }

        public Builder(GetBlockchainPlatformsBlockchainPlatformCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        public Builder items(List<GetBlockchainPlatformsBlockchainPlatformCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetBlockchainPlatformsBlockchainPlatformCollectionItem... items) {
            return items(List.of(items));
        }        public GetBlockchainPlatformsBlockchainPlatformCollection build() {
            return new GetBlockchainPlatformsBlockchainPlatformCollection(items);
        }
    }
}
