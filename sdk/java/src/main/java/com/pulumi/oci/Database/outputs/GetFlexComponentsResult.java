// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Database.outputs.GetFlexComponentsFilter;
import com.pulumi.oci.Database.outputs.GetFlexComponentsFlexComponentCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetFlexComponentsResult {
    private final String compartmentId;
    private final @Nullable List<GetFlexComponentsFilter> filters;
    /**
     * @return The list of flex_component_collection.
     * 
     */
    private final List<GetFlexComponentsFlexComponentCollection> flexComponentCollections;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return The name of the Flex Component used for the DB system.
     * 
     */
    private final @Nullable String name;

    @CustomType.Constructor
    private GetFlexComponentsResult(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("filters") @Nullable List<GetFlexComponentsFilter> filters,
        @CustomType.Parameter("flexComponentCollections") List<GetFlexComponentsFlexComponentCollection> flexComponentCollections,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("name") @Nullable String name) {
        this.compartmentId = compartmentId;
        this.filters = filters;
        this.flexComponentCollections = flexComponentCollections;
        this.id = id;
        this.name = name;
    }

    public String compartmentId() {
        return this.compartmentId;
    }
    public List<GetFlexComponentsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The list of flex_component_collection.
     * 
     */
    public List<GetFlexComponentsFlexComponentCollection> flexComponentCollections() {
        return this.flexComponentCollections;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The name of the Flex Component used for the DB system.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFlexComponentsResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private @Nullable List<GetFlexComponentsFilter> filters;
        private List<GetFlexComponentsFlexComponentCollection> flexComponentCollections;
        private String id;
        private @Nullable String name;

        public Builder() {
    	      // Empty
        }

        public Builder(GetFlexComponentsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.flexComponentCollections = defaults.flexComponentCollections;
    	      this.id = defaults.id;
    	      this.name = defaults.name;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder filters(@Nullable List<GetFlexComponentsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetFlexComponentsFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder flexComponentCollections(List<GetFlexComponentsFlexComponentCollection> flexComponentCollections) {
            this.flexComponentCollections = Objects.requireNonNull(flexComponentCollections);
            return this;
        }
        public Builder flexComponentCollections(GetFlexComponentsFlexComponentCollection... flexComponentCollections) {
            return flexComponentCollections(List.of(flexComponentCollections));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder name(@Nullable String name) {
            this.name = name;
            return this;
        }        public GetFlexComponentsResult build() {
            return new GetFlexComponentsResult(compartmentId, filters, flexComponentCollections, id, name);
        }
    }
}
