// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.VnMonitoring.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.VnMonitoring.outputs.GetPathAnalyzerTestsFilter;
import com.pulumi.oci.VnMonitoring.outputs.GetPathAnalyzerTestsPathAnalyzerTestCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetPathAnalyzerTestsResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `PathAnalyzerTest` resource&#39;s compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetPathAnalyzerTestsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of path_analyzer_test_collection.
     * 
     */
    private List<GetPathAnalyzerTestsPathAnalyzerTestCollection> pathAnalyzerTestCollections;
    /**
     * @return The current state of the `PathAnalyzerTest` resource.
     * 
     */
    private @Nullable String state;

    private GetPathAnalyzerTestsResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `PathAnalyzerTest` resource&#39;s compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetPathAnalyzerTestsFilter> filters() {
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
     * @return The list of path_analyzer_test_collection.
     * 
     */
    public List<GetPathAnalyzerTestsPathAnalyzerTestCollection> pathAnalyzerTestCollections() {
        return this.pathAnalyzerTestCollections;
    }
    /**
     * @return The current state of the `PathAnalyzerTest` resource.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPathAnalyzerTestsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetPathAnalyzerTestsFilter> filters;
        private String id;
        private List<GetPathAnalyzerTestsPathAnalyzerTestCollection> pathAnalyzerTestCollections;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetPathAnalyzerTestsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.pathAnalyzerTestCollections = defaults.pathAnalyzerTestCollections;
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
        public Builder filters(@Nullable List<GetPathAnalyzerTestsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetPathAnalyzerTestsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder pathAnalyzerTestCollections(List<GetPathAnalyzerTestsPathAnalyzerTestCollection> pathAnalyzerTestCollections) {
            this.pathAnalyzerTestCollections = Objects.requireNonNull(pathAnalyzerTestCollections);
            return this;
        }
        public Builder pathAnalyzerTestCollections(GetPathAnalyzerTestsPathAnalyzerTestCollection... pathAnalyzerTestCollections) {
            return pathAnalyzerTestCollections(List.of(pathAnalyzerTestCollections));
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        public GetPathAnalyzerTestsResult build() {
            final var o = new GetPathAnalyzerTestsResult();
            o.compartmentId = compartmentId;
            o.displayName = displayName;
            o.filters = filters;
            o.id = id;
            o.pathAnalyzerTestCollections = pathAnalyzerTestCollections;
            o.state = state;
            return o;
        }
    }
}