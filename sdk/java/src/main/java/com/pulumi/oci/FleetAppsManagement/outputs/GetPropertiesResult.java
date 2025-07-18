// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.outputs.GetPropertiesFilter;
import com.pulumi.oci.FleetAppsManagement.outputs.GetPropertiesPropertyCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetPropertiesResult {
    /**
     * @return Compartment OCID
     * 
     */
    private @Nullable String compartmentId;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.  Example: `My new resource`
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetPropertiesFilter> filters;
    /**
     * @return The OCID of the resource.
     * 
     */
    private @Nullable String id;
    /**
     * @return The list of property_collection.
     * 
     */
    private List<GetPropertiesPropertyCollection> propertyCollections;
    /**
     * @return The scope of the property.
     * 
     */
    private @Nullable String scope;
    /**
     * @return The current state of the Property.
     * 
     */
    private @Nullable String state;
    /**
     * @return The type of the property.
     * 
     */
    private @Nullable String type;

    private GetPropertiesResult() {}
    /**
     * @return Compartment OCID
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.  Example: `My new resource`
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetPropertiesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The OCID of the resource.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return The list of property_collection.
     * 
     */
    public List<GetPropertiesPropertyCollection> propertyCollections() {
        return this.propertyCollections;
    }
    /**
     * @return The scope of the property.
     * 
     */
    public Optional<String> scope() {
        return Optional.ofNullable(this.scope);
    }
    /**
     * @return The current state of the Property.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    /**
     * @return The type of the property.
     * 
     */
    public Optional<String> type() {
        return Optional.ofNullable(this.type);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPropertiesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetPropertiesFilter> filters;
        private @Nullable String id;
        private List<GetPropertiesPropertyCollection> propertyCollections;
        private @Nullable String scope;
        private @Nullable String state;
        private @Nullable String type;
        public Builder() {}
        public Builder(GetPropertiesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.propertyCollections = defaults.propertyCollections;
    	      this.scope = defaults.scope;
    	      this.state = defaults.state;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder compartmentId(@Nullable String compartmentId) {

            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetPropertiesFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetPropertiesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(@Nullable String id) {

            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder propertyCollections(List<GetPropertiesPropertyCollection> propertyCollections) {
            if (propertyCollections == null) {
              throw new MissingRequiredPropertyException("GetPropertiesResult", "propertyCollections");
            }
            this.propertyCollections = propertyCollections;
            return this;
        }
        public Builder propertyCollections(GetPropertiesPropertyCollection... propertyCollections) {
            return propertyCollections(List.of(propertyCollections));
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
        public Builder type(@Nullable String type) {

            this.type = type;
            return this;
        }
        public GetPropertiesResult build() {
            final var _resultValue = new GetPropertiesResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.propertyCollections = propertyCollections;
            _resultValue.scope = scope;
            _resultValue.state = state;
            _resultValue.type = type;
            return _resultValue;
        }
    }
}
