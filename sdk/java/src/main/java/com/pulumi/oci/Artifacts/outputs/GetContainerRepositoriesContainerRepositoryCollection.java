// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Artifacts.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Artifacts.outputs.GetContainerRepositoriesContainerRepositoryCollectionItem;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetContainerRepositoriesContainerRepositoryCollection {
    /**
     * @return Total number of images.
     * 
     */
    private final Integer imageCount;
    private final List<GetContainerRepositoriesContainerRepositoryCollectionItem> items;
    /**
     * @return Total number of layers.
     * 
     */
    private final Integer layerCount;
    /**
     * @return Total storage in bytes consumed by layers.
     * 
     */
    private final String layersSizeInBytes;
    private final Integer remainingItemsCount;
    private final Integer repositoryCount;

    @CustomType.Constructor
    private GetContainerRepositoriesContainerRepositoryCollection(
        @CustomType.Parameter("imageCount") Integer imageCount,
        @CustomType.Parameter("items") List<GetContainerRepositoriesContainerRepositoryCollectionItem> items,
        @CustomType.Parameter("layerCount") Integer layerCount,
        @CustomType.Parameter("layersSizeInBytes") String layersSizeInBytes,
        @CustomType.Parameter("remainingItemsCount") Integer remainingItemsCount,
        @CustomType.Parameter("repositoryCount") Integer repositoryCount) {
        this.imageCount = imageCount;
        this.items = items;
        this.layerCount = layerCount;
        this.layersSizeInBytes = layersSizeInBytes;
        this.remainingItemsCount = remainingItemsCount;
        this.repositoryCount = repositoryCount;
    }

    /**
     * @return Total number of images.
     * 
     */
    public Integer imageCount() {
        return this.imageCount;
    }
    public List<GetContainerRepositoriesContainerRepositoryCollectionItem> items() {
        return this.items;
    }
    /**
     * @return Total number of layers.
     * 
     */
    public Integer layerCount() {
        return this.layerCount;
    }
    /**
     * @return Total storage in bytes consumed by layers.
     * 
     */
    public String layersSizeInBytes() {
        return this.layersSizeInBytes;
    }
    public Integer remainingItemsCount() {
        return this.remainingItemsCount;
    }
    public Integer repositoryCount() {
        return this.repositoryCount;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetContainerRepositoriesContainerRepositoryCollection defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private Integer imageCount;
        private List<GetContainerRepositoriesContainerRepositoryCollectionItem> items;
        private Integer layerCount;
        private String layersSizeInBytes;
        private Integer remainingItemsCount;
        private Integer repositoryCount;

        public Builder() {
    	      // Empty
        }

        public Builder(GetContainerRepositoriesContainerRepositoryCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.imageCount = defaults.imageCount;
    	      this.items = defaults.items;
    	      this.layerCount = defaults.layerCount;
    	      this.layersSizeInBytes = defaults.layersSizeInBytes;
    	      this.remainingItemsCount = defaults.remainingItemsCount;
    	      this.repositoryCount = defaults.repositoryCount;
        }

        public Builder imageCount(Integer imageCount) {
            this.imageCount = Objects.requireNonNull(imageCount);
            return this;
        }
        public Builder items(List<GetContainerRepositoriesContainerRepositoryCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetContainerRepositoriesContainerRepositoryCollectionItem... items) {
            return items(List.of(items));
        }
        public Builder layerCount(Integer layerCount) {
            this.layerCount = Objects.requireNonNull(layerCount);
            return this;
        }
        public Builder layersSizeInBytes(String layersSizeInBytes) {
            this.layersSizeInBytes = Objects.requireNonNull(layersSizeInBytes);
            return this;
        }
        public Builder remainingItemsCount(Integer remainingItemsCount) {
            this.remainingItemsCount = Objects.requireNonNull(remainingItemsCount);
            return this;
        }
        public Builder repositoryCount(Integer repositoryCount) {
            this.repositoryCount = Objects.requireNonNull(repositoryCount);
            return this;
        }        public GetContainerRepositoriesContainerRepositoryCollection build() {
            return new GetContainerRepositoriesContainerRepositoryCollection(imageCount, items, layerCount, layersSizeInBytes, remainingItemsCount, repositoryCount);
        }
    }
}
