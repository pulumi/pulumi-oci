// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetImagesFilter;
import com.pulumi.oci.Core.outputs.GetImagesImage;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetImagesResult {
    /**
     * @return The OCID of the compartment containing the instance you want to use as the basis for the image.
     * 
     */
    private String compartmentId;
    /**
     * @return A user-friendly name for the image. It does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetImagesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of images.
     * 
     */
    private List<GetImagesImage> images;
    /**
     * @return The image&#39;s operating system.  Example: `Oracle Linux`
     * 
     */
    private @Nullable String operatingSystem;
    /**
     * @return The image&#39;s operating system version.  Example: `7.2`
     * 
     */
    private @Nullable String operatingSystemVersion;
    private @Nullable String shape;
    private @Nullable String sortBy;
    private @Nullable String sortOrder;
    /**
     * @return The current state of the image.
     * 
     */
    private @Nullable String state;

    private GetImagesResult() {}
    /**
     * @return The OCID of the compartment containing the instance you want to use as the basis for the image.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return A user-friendly name for the image. It does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetImagesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The list of images.
     * 
     */
    public List<GetImagesImage> images() {
        return this.images;
    }
    /**
     * @return The image&#39;s operating system.  Example: `Oracle Linux`
     * 
     */
    public Optional<String> operatingSystem() {
        return Optional.ofNullable(this.operatingSystem);
    }
    /**
     * @return The image&#39;s operating system version.  Example: `7.2`
     * 
     */
    public Optional<String> operatingSystemVersion() {
        return Optional.ofNullable(this.operatingSystemVersion);
    }
    public Optional<String> shape() {
        return Optional.ofNullable(this.shape);
    }
    public Optional<String> sortBy() {
        return Optional.ofNullable(this.sortBy);
    }
    public Optional<String> sortOrder() {
        return Optional.ofNullable(this.sortOrder);
    }
    /**
     * @return The current state of the image.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetImagesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetImagesFilter> filters;
        private String id;
        private List<GetImagesImage> images;
        private @Nullable String operatingSystem;
        private @Nullable String operatingSystemVersion;
        private @Nullable String shape;
        private @Nullable String sortBy;
        private @Nullable String sortOrder;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetImagesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.images = defaults.images;
    	      this.operatingSystem = defaults.operatingSystem;
    	      this.operatingSystemVersion = defaults.operatingSystemVersion;
    	      this.shape = defaults.shape;
    	      this.sortBy = defaults.sortBy;
    	      this.sortOrder = defaults.sortOrder;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetImagesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetImagesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder images(List<GetImagesImage> images) {
            this.images = Objects.requireNonNull(images);
            return this;
        }
        public Builder images(GetImagesImage... images) {
            return images(List.of(images));
        }
        @CustomType.Setter
        public Builder operatingSystem(@Nullable String operatingSystem) {
            this.operatingSystem = operatingSystem;
            return this;
        }
        @CustomType.Setter
        public Builder operatingSystemVersion(@Nullable String operatingSystemVersion) {
            this.operatingSystemVersion = operatingSystemVersion;
            return this;
        }
        @CustomType.Setter
        public Builder shape(@Nullable String shape) {
            this.shape = shape;
            return this;
        }
        @CustomType.Setter
        public Builder sortBy(@Nullable String sortBy) {
            this.sortBy = sortBy;
            return this;
        }
        @CustomType.Setter
        public Builder sortOrder(@Nullable String sortOrder) {
            this.sortOrder = sortOrder;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        public GetImagesResult build() {
            final var o = new GetImagesResult();
            o.compartmentId = compartmentId;
            o.displayName = displayName;
            o.filters = filters;
            o.id = id;
            o.images = images;
            o.operatingSystem = operatingSystem;
            o.operatingSystemVersion = operatingSystemVersion;
            o.shape = shape;
            o.sortBy = sortBy;
            o.sortOrder = sortOrder;
            o.state = state;
            return o;
        }
    }
}