// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerInstances.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ContainerInstances.outputs.GetContainerInstanceShapesContainerInstanceShapeCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetContainerInstanceShapesContainerInstanceShapeCollection {
    /**
     * @return List of shapes.
     * 
     */
    private List<GetContainerInstanceShapesContainerInstanceShapeCollectionItem> items;

    private GetContainerInstanceShapesContainerInstanceShapeCollection() {}
    /**
     * @return List of shapes.
     * 
     */
    public List<GetContainerInstanceShapesContainerInstanceShapeCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetContainerInstanceShapesContainerInstanceShapeCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetContainerInstanceShapesContainerInstanceShapeCollectionItem> items;
        public Builder() {}
        public Builder(GetContainerInstanceShapesContainerInstanceShapeCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetContainerInstanceShapesContainerInstanceShapeCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetContainerInstanceShapesContainerInstanceShapeCollectionItem... items) {
            return items(List.of(items));
        }
        public GetContainerInstanceShapesContainerInstanceShapeCollection build() {
            final var o = new GetContainerInstanceShapesContainerInstanceShapeCollection();
            o.items = items;
            return o;
        }
    }
}