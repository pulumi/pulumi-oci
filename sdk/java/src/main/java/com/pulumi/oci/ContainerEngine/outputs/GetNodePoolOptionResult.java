// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ContainerEngine.outputs.GetNodePoolOptionSource;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetNodePoolOptionResult {
    private @Nullable String compartmentId;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return Deprecated. See sources. When creating a node pool, only image names contained in this property can be passed to the `node_image_name` property.
     * 
     */
    private List<String> images;
    /**
     * @return Available Kubernetes versions.
     * 
     */
    private List<String> kubernetesVersions;
    private String nodePoolOptionId;
    /**
     * @return Available shapes for nodes.
     * 
     */
    private List<String> shapes;
    /**
     * @return Available source of the node.
     * 
     */
    private List<GetNodePoolOptionSource> sources;

    private GetNodePoolOptionResult() {}
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
     * @return Deprecated. See sources. When creating a node pool, only image names contained in this property can be passed to the `node_image_name` property.
     * 
     */
    public List<String> images() {
        return this.images;
    }
    /**
     * @return Available Kubernetes versions.
     * 
     */
    public List<String> kubernetesVersions() {
        return this.kubernetesVersions;
    }
    public String nodePoolOptionId() {
        return this.nodePoolOptionId;
    }
    /**
     * @return Available shapes for nodes.
     * 
     */
    public List<String> shapes() {
        return this.shapes;
    }
    /**
     * @return Available source of the node.
     * 
     */
    public List<GetNodePoolOptionSource> sources() {
        return this.sources;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNodePoolOptionResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String compartmentId;
        private String id;
        private List<String> images;
        private List<String> kubernetesVersions;
        private String nodePoolOptionId;
        private List<String> shapes;
        private List<GetNodePoolOptionSource> sources;
        public Builder() {}
        public Builder(GetNodePoolOptionResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.id = defaults.id;
    	      this.images = defaults.images;
    	      this.kubernetesVersions = defaults.kubernetesVersions;
    	      this.nodePoolOptionId = defaults.nodePoolOptionId;
    	      this.shapes = defaults.shapes;
    	      this.sources = defaults.sources;
        }

        @CustomType.Setter
        public Builder compartmentId(@Nullable String compartmentId) {
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder images(List<String> images) {
            this.images = Objects.requireNonNull(images);
            return this;
        }
        public Builder images(String... images) {
            return images(List.of(images));
        }
        @CustomType.Setter
        public Builder kubernetesVersions(List<String> kubernetesVersions) {
            this.kubernetesVersions = Objects.requireNonNull(kubernetesVersions);
            return this;
        }
        public Builder kubernetesVersions(String... kubernetesVersions) {
            return kubernetesVersions(List.of(kubernetesVersions));
        }
        @CustomType.Setter
        public Builder nodePoolOptionId(String nodePoolOptionId) {
            this.nodePoolOptionId = Objects.requireNonNull(nodePoolOptionId);
            return this;
        }
        @CustomType.Setter
        public Builder shapes(List<String> shapes) {
            this.shapes = Objects.requireNonNull(shapes);
            return this;
        }
        public Builder shapes(String... shapes) {
            return shapes(List.of(shapes));
        }
        @CustomType.Setter
        public Builder sources(List<GetNodePoolOptionSource> sources) {
            this.sources = Objects.requireNonNull(sources);
            return this;
        }
        public Builder sources(GetNodePoolOptionSource... sources) {
            return sources(List.of(sources));
        }
        public GetNodePoolOptionResult build() {
            final var o = new GetNodePoolOptionResult();
            o.compartmentId = compartmentId;
            o.id = id;
            o.images = images;
            o.kubernetesVersions = kubernetesVersions;
            o.nodePoolOptionId = nodePoolOptionId;
            o.shapes = shapes;
            o.sources = sources;
            return o;
        }
    }
}