// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Dns.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Dns.outputs.GetViewsFilter;
import com.pulumi.oci.Dns.outputs.GetViewsView;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetViewsResult {
    /**
     * @return The OCID of the owning compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return The display name of the view.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetViewsFilter> filters;
    /**
     * @return The OCID of the view.
     * 
     */
    private @Nullable String id;
    private @Nullable String scope;
    /**
     * @return The current state of the resource.
     * 
     */
    private @Nullable String state;
    /**
     * @return The list of views.
     * 
     */
    private List<GetViewsView> views;

    private GetViewsResult() {}
    /**
     * @return The OCID of the owning compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The display name of the view.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetViewsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The OCID of the view.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    public Optional<String> scope() {
        return Optional.ofNullable(this.scope);
    }
    /**
     * @return The current state of the resource.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    /**
     * @return The list of views.
     * 
     */
    public List<GetViewsView> views() {
        return this.views;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetViewsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetViewsFilter> filters;
        private @Nullable String id;
        private @Nullable String scope;
        private @Nullable String state;
        private List<GetViewsView> views;
        public Builder() {}
        public Builder(GetViewsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.scope = defaults.scope;
    	      this.state = defaults.state;
    	      this.views = defaults.views;
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
        public Builder filters(@Nullable List<GetViewsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetViewsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(@Nullable String id) {
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder scope(@Nullable String scope) {
            this.scope = scope;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder views(List<GetViewsView> views) {
            this.views = Objects.requireNonNull(views);
            return this;
        }
        public Builder views(GetViewsView... views) {
            return views(List.of(views));
        }
        public GetViewsResult build() {
            final var o = new GetViewsResult();
            o.compartmentId = compartmentId;
            o.displayName = displayName;
            o.filters = filters;
            o.id = id;
            o.scope = scope;
            o.state = state;
            o.views = views;
            return o;
        }
    }
}