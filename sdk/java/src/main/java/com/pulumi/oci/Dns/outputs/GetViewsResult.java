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
    private final String compartmentId;
    /**
     * @return The display name of the view.
     * 
     */
    private final @Nullable String displayName;
    private final @Nullable List<GetViewsFilter> filters;
    /**
     * @return The OCID of the view.
     * 
     */
    private final @Nullable String id;
    private final String scope;
    /**
     * @return The current state of the resource.
     * 
     */
    private final @Nullable String state;
    /**
     * @return The list of views.
     * 
     */
    private final List<GetViewsView> views;

    @CustomType.Constructor
    private GetViewsResult(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("displayName") @Nullable String displayName,
        @CustomType.Parameter("filters") @Nullable List<GetViewsFilter> filters,
        @CustomType.Parameter("id") @Nullable String id,
        @CustomType.Parameter("scope") String scope,
        @CustomType.Parameter("state") @Nullable String state,
        @CustomType.Parameter("views") List<GetViewsView> views) {
        this.compartmentId = compartmentId;
        this.displayName = displayName;
        this.filters = filters;
        this.id = id;
        this.scope = scope;
        this.state = state;
        this.views = views;
    }

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
    public String scope() {
        return this.scope;
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

    public static final class Builder {
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetViewsFilter> filters;
        private @Nullable String id;
        private String scope;
        private @Nullable String state;
        private List<GetViewsView> views;

        public Builder() {
    	      // Empty
        }

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

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        public Builder filters(@Nullable List<GetViewsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetViewsFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(@Nullable String id) {
            this.id = id;
            return this;
        }
        public Builder scope(String scope) {
            this.scope = Objects.requireNonNull(scope);
            return this;
        }
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        public Builder views(List<GetViewsView> views) {
            this.views = Objects.requireNonNull(views);
            return this;
        }
        public Builder views(GetViewsView... views) {
            return views(List.of(views));
        }        public GetViewsResult build() {
            return new GetViewsResult(compartmentId, displayName, filters, id, scope, state, views);
        }
    }
}
