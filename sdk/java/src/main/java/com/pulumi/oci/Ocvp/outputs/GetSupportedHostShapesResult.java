// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Ocvp.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Ocvp.outputs.GetSupportedHostShapesFilter;
import com.pulumi.oci.Ocvp.outputs.GetSupportedHostShapesItem;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetSupportedHostShapesResult {
    private String compartmentId;
    private @Nullable List<GetSupportedHostShapesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of the supported compute shapes for ESXi hosts.
     * 
     */
    private List<GetSupportedHostShapesItem> items;
    /**
     * @return The name of the supported compute shape.
     * 
     */
    private @Nullable String name;
    private @Nullable String sddcType;

    private GetSupportedHostShapesResult() {}
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<GetSupportedHostShapesFilter> filters() {
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
     * @return The list of the supported compute shapes for ESXi hosts.
     * 
     */
    public List<GetSupportedHostShapesItem> items() {
        return this.items;
    }
    /**
     * @return The name of the supported compute shape.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    public Optional<String> sddcType() {
        return Optional.ofNullable(this.sddcType);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSupportedHostShapesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable List<GetSupportedHostShapesFilter> filters;
        private String id;
        private List<GetSupportedHostShapesItem> items;
        private @Nullable String name;
        private @Nullable String sddcType;
        public Builder() {}
        public Builder(GetSupportedHostShapesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.items = defaults.items;
    	      this.name = defaults.name;
    	      this.sddcType = defaults.sddcType;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetSupportedHostShapesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetSupportedHostShapesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder items(List<GetSupportedHostShapesItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetSupportedHostShapesItem... items) {
            return items(List.of(items));
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder sddcType(@Nullable String sddcType) {
            this.sddcType = sddcType;
            return this;
        }
        public GetSupportedHostShapesResult build() {
            final var o = new GetSupportedHostShapesResult();
            o.compartmentId = compartmentId;
            o.filters = filters;
            o.id = id;
            o.items = items;
            o.name = name;
            o.sddcType = sddcType;
            return o;
        }
    }
}