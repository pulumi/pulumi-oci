// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataCatalog.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataCatalog.outputs.GetMetastoresFilter;
import com.pulumi.oci.DataCatalog.outputs.GetMetastoresMetastore;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetMetastoresResult {
    /**
     * @return OCID of the compartment which holds the metastore.
     * 
     */
    private String compartmentId;
    /**
     * @return Mutable name of the metastore.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetMetastoresFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of metastores.
     * 
     */
    private List<GetMetastoresMetastore> metastores;
    /**
     * @return The current state of the metastore.
     * 
     */
    private @Nullable String state;

    private GetMetastoresResult() {}
    /**
     * @return OCID of the compartment which holds the metastore.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Mutable name of the metastore.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetMetastoresFilter> filters() {
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
     * @return The list of metastores.
     * 
     */
    public List<GetMetastoresMetastore> metastores() {
        return this.metastores;
    }
    /**
     * @return The current state of the metastore.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMetastoresResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetMetastoresFilter> filters;
        private String id;
        private List<GetMetastoresMetastore> metastores;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetMetastoresResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.metastores = defaults.metastores;
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
        public Builder filters(@Nullable List<GetMetastoresFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetMetastoresFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder metastores(List<GetMetastoresMetastore> metastores) {
            this.metastores = Objects.requireNonNull(metastores);
            return this;
        }
        public Builder metastores(GetMetastoresMetastore... metastores) {
            return metastores(List.of(metastores));
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        public GetMetastoresResult build() {
            final var o = new GetMetastoresResult();
            o.compartmentId = compartmentId;
            o.displayName = displayName;
            o.filters = filters;
            o.id = id;
            o.metastores = metastores;
            o.state = state;
            return o;
        }
    }
}